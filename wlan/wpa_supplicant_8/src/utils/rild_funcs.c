#include <cutils/sockets.h>
#include "includes.h"
#include "rild_funcs.h"
#include <assert.h>
#include "common.h"
#include "eap_common/eap_defs.h"
#include <time.h>
#include "cutils/properties.h"

#define RILD_SOCKET_NAME "rild-oem"
#define RILD_SOCKET_MD2_NAME "rild-oem-md2"
#define SIM_AKA_RAND_LEN 	16
#define SIM_SRES_LEN	4
#define SIM_KC_LEN	8
#define AKA_AUTN_LEN 16
#define AKA_AUTS_LEN 14
#define RES_MAX_LEN 16
#define IK_LEN 16
#define CK_LEN 16

inline void hextostr(const u8 *hex, u32 len, char *a)
{
	u8 i = 0;
	u8 strLen = 2*len+1;
	u32 printLen = 0;
	for(i = 0; i < len/4; i++){
		printLen += os_snprintf(a+printLen, strLen-printLen, 
								"%02x%02x%02x%02x", hex[4*i], hex[4*i+1], hex[4*i+2], hex[4*i+3]);
	}
	for (i = 0; i < len%4; i++){
		printLen += os_snprintf(a+printLen, strLen-printLen, "%02x", hex[i]);
	}
}

/* connnect to rild via socket. */
static int connectToRild(int *slot_id)
{
	int sock = -1;
	char *sock_name = RILD_SOCKET_NAME;
	struct timeval snd_timeout = {5,0};/* timeout value for sned, wait 5s */
	struct timeval rcv_timeout = {5,0};/* timeout value for recvfrom, wait 5s */
#if defined CONFIG_RILD_FUNCS_MULTI_SIM && defined CONFIG_RILD_FUNCS_MTK_DT
	char prop_buf[PROPERTY_VALUE_MAX];
#ifdef CONFIG_RILD_FUNCS_EVDO_DT
	property_get("ril.telephony.mode", prop_buf, "0");
	if (os_strncmp(prop_buf, "103", 3) == 0 || 
				os_strncmp(prop_buf, "100", 3) == 0){
		sock_name = RILD_SOCKET_MD2_NAME;
	}
#else /* CONFIG_RILD_FUNCS_EVDO_DT */
	property_get("ril.external.md", prop_buf, "0");
	if (prop_buf[0] == '1') {
		sock_name = *slot_id == 0 ? RILD_SOCKET_MD2_NAME:RILD_SOCKET_NAME;
	} else if (prop_buf[0] == '2') {
		sock_name = *slot_id == 0 ? RILD_SOCKET_NAME:RILD_SOCKET_MD2_NAME;
	} else {
		wpa_printf(MSG_ERROR, "not supported external modem value:%c", prop_buf[0]);
		return -1;
	}
#endif /* CONFIG_RILD_FUNCS_EVDO_DT */
#endif /* CONFIG_RILD_FUNCS_MULTI_SIM && CONFIG_RILD_FUNCS_MTK_DT */
	wpa_printf(MSG_DEBUG, "RIL: slot=%d, socket name=%s", *slot_id, sock_name);
	sock = socket_local_client(sock_name,ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
	if (sock <= 0 
		|| setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (void*)&snd_timeout, sizeof(struct timeval)) < 0
		|| setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void*)&rcv_timeout, sizeof(struct timeval)) < 0){
		wpa_printf(MSG_ERROR, "failure in %s, sock_name=%s, errno=%s", 
				__FUNCTION__, sock_name, strerror(errno));
		return -1;
	}
	return sock;
}

static int socketRecv(int sock, void* buf, u32 bufLen){
	int ret = -1;
	/* if recv is returned, and with errno EINTR, it means supplicant has a pending signal. 
		for this case, we should loop again to recv. No need to warry about there may be a 
		dead loop, beacuse we set the socket timeout in 5s */
	do {
		ret = recv(sock, (void*)buf, bufLen, 0);
		if (ret != bufLen)
			wpa_printf(MSG_ERROR,"%s : ret=%d, bufLen=%u, errno=%s\n",
				__FUNCTION__, ret, bufLen, strerror(errno));
	} while (ret < 0 && errno == EINTR);
	
	return ret;
}

static int setScardAuthParam(int sock, int slotId, const u8 *rand, const u8 *autn)
{
	int strLen = 0;
	int count = 1;
	int printLen = 0;
	char *strParm = NULL;
		
	assert(sock > 0);
	
	wpa_printf(MSG_DEBUG, "%s, slotId=%d, sock=%d\n", __FUNCTION__, slotId, sock);
	wpa_hexdump(MSG_DEBUG, "rand: ", rand, SIM_AKA_RAND_LEN);
	wpa_hexdump(MSG_DEBUG, "autn: ", autn!=NULL ? autn:"NULL", autn!=NULL ? AKA_AUTN_LEN:5);

	strLen = autn==NULL ? (os_strlen("EAP_SIM") + 3 + SIM_AKA_RAND_LEN * 2 + 1):
							(os_strlen("EAP_AKA") + 3 + SIM_AKA_RAND_LEN * 2 + 1 + AKA_AUTN_LEN * 2 + 1);
	strParm	= (char *)os_zalloc(strLen);
	printLen = os_snprintf(strParm, strLen, "EAP_%s,", autn==NULL ? "SIM":"AKA");
#if CONFIG_RILD_FUNCS_MULTI_SIM
	printLen += os_snprintf(strParm + printLen, strLen-printLen, "%d,", slotId);
#else
	strLen -= 2; /* if single sim, substract two bytes for slot id */
#endif
	hextostr(rand, SIM_AKA_RAND_LEN, strParm + printLen);
	printLen += 2*SIM_AKA_RAND_LEN;
	if (autn != NULL){
		printLen += os_snprintf(strParm+printLen, strLen-printLen, ",");
		hextostr(autn, AKA_AUTN_LEN, strParm + printLen);
		printLen += 2*AKA_AUTN_LEN;
	}
	/* if printLen +1 == strLen, it means that there is no error */
	if (printLen+1 != strLen) {
		wpa_printf(MSG_ERROR, "compose auth param error, printLen=%d, strLen=%d", printLen, strLen);
		return -1;
	}
	wpa_printf(MSG_DEBUG, "Len:%d, %s will sent to rild\n", strLen, strParm);

	/*this socket is in blocking mode, so if the return value of send is not the length
   		we're expected, it may be timeout while send */
	if (send(sock, &count, sizeof(count), 0) != sizeof(count)
		|| send(sock, &strLen, sizeof(strLen), 0) != sizeof(strLen)
		|| send(sock, strParm, strLen, 0) != strLen){
		os_free(strParm);
		wpa_printf(MSG_DEBUG, "send data to rild error:%s in %s\n", __FUNCTION__, strerror(errno));
		return -1;
	}
	os_free(strParm);
	return 0;
}

static int parseSimResult(const char *strParm, int strLen, u8 *sres, u8 *kc)
{	
	int ret = 0;
	wpa_printf(MSG_DEBUG, "%s (%d) %s\n", __FUNCTION__, strLen, (char *)strParm);
	
	if(0 == os_strncmp(strParm, "ERROR", os_strlen("ERROR")))
		return -1;
	/*strncpy(sres, strParm, 4);*/
	/*strncpy(kc, strParm + 4, 8);*/
	ret = hexstr2bin(strParm, sres, SIM_SRES_LEN);
	ret = hexstr2bin(strParm+2*SIM_SRES_LEN, kc, SIM_KC_LEN);
	return ret;	
}


static void parseAkaSuccess(const char* str, u8 *res, size_t *res_len,
			u8 *ck, u8 *ik)
{
	u32 len = 0;
	u8 kc[16];
	u8 j = 0;
	u8 *results[] = {res, ck, ik, kc};
	char *results_name[] = {"parseAkaSuccess res", "parseAkaSuccess ck",
							"parseAkaSuccess ik", "parseAkaSuccess kc"};

	*res_len = hex2byte(str);
	for (; j<sizeof(results)/sizeof(u8*); j++){
		len = hex2byte(str);
		str += 2;
		hexstr2bin(str, results[j], len);
		wpa_hexdump(MSG_DEBUG, results_name[j], results[j], len);
		str += len*2;
	}
}

static void parseAkaFailure(const char* str, u8 *auts)
{
	u8 len = 0;

	len = hex2byte(str);
	hexstr2bin(str+2, auts, len);
	wpa_hexdump(MSG_DEBUG, "parseAkaFailure auts ", auts, len);
}

static int parseAkaResult(const char *strParm, int strLen,
			u8 *res, size_t *res_len,
		     	u8 *ik, u8 *ck, u8 *auts)
{
	int ret = -1;

	wpa_printf(MSG_DEBUG, "%s %s\n", __FUNCTION__, strParm);	
	
	if(0 == os_strncmp(strParm, "DB", os_strlen("DB"))){
		parseAkaSuccess(strParm + 2, res, res_len, ck, ik);		
		return 0;
	}else if(0 == os_strncmp(strParm, "DC", os_strlen("DC"))){
		parseAkaFailure(strParm + 2, auts);
		
	}else{
		wpa_printf(MSG_DEBUG, "%s unknow string. %s\n", 
			__FUNCTION__, strParm);
	}

	return -1;	

}


//output function

//1 3G security_parameters context
static char* queryScardAuthResult(int sock, unsigned int *strLen)
{
	char *strParm = NULL;
	
	assert(sock > 0);

	wpa_printf(MSG_DEBUG,"%s, sock=%d\n", __FUNCTION__, sock);	

	/*this socket is in blocking mode, so if the return value of send is not the length
   		we're expected, it may be timeout while send */
	if(socketRecv(sock,(void*)strLen, sizeof(*strLen)) != sizeof(*strLen)){
		return NULL;
	}
	
	strParm = (char *)os_zalloc(*strLen + 1);
	if (strParm == NULL){
		wpa_printf(MSG_ERROR,"memory allocate failed in %s", __FUNCTION__);
		return NULL;
	}
	if(socketRecv(sock, (void*)strParm, *strLen) != *strLen){
		os_free(strParm);
	}
	return strParm;
}

//uninitilization;
inline int disconnectWithRild(int sock)
{
	assert(sock > 0);
	wpa_printf(MSG_DEBUG, "%s, sock=%d", __FUNCTION__, sock);
	return close(sock);
}

/**
 * scard_gsm_auth - Run GSM authentication command on SIM card
 * @scard: Pointer to private data from scard_init()
 * @_rand: 16-byte RAND value from HLR/AuC
 * @sres: 4-byte buffer for SRES
 * @kc: 8-byte buffer for Kc
 * Returns: 0 on success, -1 if SIM/USIM connection has not been initialized,
 * -2 if authentication command execution fails, -3 if unknown response code
 * for authentication command is received, -4 if reading of response fails,
 * -5 if if response data is of unexpected length
 *
 * This function performs GSM authentication using SIM/USIM card and the
 * provided RAND value from HLR/AuC. If authentication command can be completed
 * successfully, SRES and Kc values will be written into sres and kc buffers.
 */
int scard_gsm_auth(int slotId, const unsigned char *_rand,
		   unsigned char *sres, unsigned char *kc)
{
	unsigned int len;
	int sock = -1;
	int ret = -1;
	char *result = NULL;

	wpa_hexdump(MSG_DEBUG, "SCARD: GSM auth - RAND", _rand, 16);

	sock = connectToRild(&slotId);
	if (sock < 0)
		return -1;
	if(!setScardAuthParam(sock, slotId, _rand, NULL)){
		result = queryScardAuthResult(sock, &len);
		if (result){
			ret = parseSimResult(result, len, sres, kc);
			os_free(result);
		}
	}
	disconnectWithRild(sock);
	wpa_printf(MSG_DEBUG, "%s is %s", __FUNCTION__, ret==0 ? "success":"failure");
	if (!ret){
		wpa_hexdump(MSG_DEBUG, "SCARD: GSM auth - SRES", sres, 4);
		wpa_hexdump(MSG_DEBUG, "SCARD: GSM auth - Kc", kc, 8);
	}
	return ret;
}


/**
 * scard_umts_auth - Run UMTS authentication command on USIM card
 * @scard: Pointer to private data from scard_init()
 * @_rand: 16-byte RAND value from HLR/AuC
 * @autn: 16-byte AUTN value from HLR/AuC
 * @res: 16-byte buffer for RES
 * @res_len: Variable that will be set to RES length
 * @ik: 16-byte buffer for IK
 * @ck: 16-byte buffer for CK
 * @auts: 14-byte buffer for AUTS
 * Returns: 0 on success, -1 on failure, or -2 if USIM reports synchronization
 * failure
 *
 * This function performs AKA authentication using USIM card and the provided
 * RAND and AUTN values from HLR/AuC. If authentication command can be
 * completed successfully, RES, IK, and CK values will be written into provided
 * buffers and res_len is set to length of received RES value. If USIM reports
 * synchronization failure, the received AUTS value will be written into auts
 * buffer. In this case, RES, IK, and CK are not valid.
 */
int scard_umts_auth(int slotId, const unsigned char *_rand,
		    const unsigned char *autn,
		    unsigned char *res, size_t *res_len,
		    unsigned char *ik, unsigned char *ck, unsigned char *auts)
{
	unsigned int len;
	int sock = -1;
	int ret = -1;
	char *result = NULL;

	wpa_hexdump(MSG_DEBUG, "SCARD: UMTS auth - RAND", _rand, SIM_AKA_RAND_LEN);
	wpa_hexdump(MSG_DEBUG, "SCARD: UMTS auth - AUTN", autn, AKA_AUTN_LEN);						
				
	sock = connectToRild(&slotId);
	if (sock < 0)
		return -1;
	if(!setScardAuthParam(sock, slotId, _rand, autn)){
		result = queryScardAuthResult(sock, &len);
		if (result){
			ret = parseAkaResult(result, len, res, res_len, ik, ck, auts);
			os_free(result);
		}
	}
	disconnectWithRild(sock);
	wpa_printf(MSG_DEBUG, "%s is %s", __FUNCTION__, ret==0 ? "success":"failure");
	return ret;		
}

void getSoftSimPassword(u8 method, char *passwd) {
	char *def_passwd = NULL;
	char *prop_name = NULL;
	switch (method){
		case EAP_TYPE_SIM:
			prop_name = "wlan.softsim.sim";
			def_passwd = "90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581";
			break;
		case EAP_TYPE_AKA:
			prop_name = "wlan.softsim.aka";
			def_passwd = "90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000000";
			break;
		case EAP_TYPE_AKA_PRIME:
			prop_name = "wlan.softsim.akaprime";
			def_passwd = "5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:16f3b3f70fc1";
			break;
		default:
			break;
	}
	property_get(prop_name, passwd, def_passwd);
}

#ifdef CONFIG_GET_IMSI_FROM_PROPERTY
size_t generate_nai (char *nai, unsigned int allowMethod, int slot_id) {
/* read imsi from property and build NAI, don't use the one from UI. this feature request from LGE */
	char propBuf[PROPERTY_VALUE_MAX];
	char IMSI[16]="", mcc[4]={0}, mnc[4]={0};
	char *temp = NULL;
	int len = 0;
	if(property_get("gsm.sim.operator.imsi", propBuf, NULL) < 15) {
		wpa_printf(MSG_ERROR,"EAP: gsm.sim.operator.imsi is not set yet");
		return 0;
	}
	if (slot_id == 1) {
		temp = os_strchr(propBuf, ',');
		os_memcpy(IMSI, temp+1, 15);
	} else if (slot_id == 0)
		os_memcpy(IMSI, propBuf, 15);

	os_memset(propBuf, 0, sizeof(propBuf));
	if ((len = property_get("gsm.sim.operator.numeric", propBuf, NULL)) < 5) {
		wpa_printf(MSG_ERROR,"EAP: gsm.sim.operator.numeric is not set yet");
		return 0;
	}
	
	temp = os_strchr(propBuf, ',');
	if (slot_id == 1) {
		temp++;
		len = os_strlen(temp);
	} else if (slot_id == 0) {
		if (temp)	
			len = (int)(temp - propBuf);
		temp = propBuf;
	}
	
	if (len == 6) {
		mnc[2] = temp[5];
		mnc[1] = temp[4];
		mnc[0] = temp[3];
	} else if (len == 5) {
		mnc[2] = temp[4];
		mnc[1] = temp[3];
		mnc[0] = '0';
	}
	os_memcpy(mcc, temp, 3);
	sprintf(nai,"1%s@wlan.mnc%s.mcc%s.3gppnetwork.org", IMSI, mnc, mcc);
	if (allowMethod == EAP_TYPE_AKA_PRIME)
		nai[0] = '6';
	else if (allowMethod == EAP_TYPE_AKA)
		nai[0] = '0';
	wpa_printf(MSG_DEBUG, "EAP: NAI is %s", nai);
	return os_strlen(nai);
}
#endif

