#ifndef RILD_FUNCS_H
#define RILD_FUNCS_H

int scard_gsm_auth(int slotId, const unsigned char *_rand,
		   unsigned char *sres, unsigned char *kc);
int scard_umts_auth(int slotId, const unsigned char *_rand,
		    const unsigned char *autn,
		    unsigned char *res, size_t *res_len,
		    unsigned char *ik, unsigned char *ck, unsigned char *auts);
void getSoftSimPassword(unsigned char method, char *passwd);
#ifdef CONFIG_GET_IMSI_FROM_PROPERTY
size_t generate_nai (char *nai, unsigned int allowMethod, int slot_id);
#endif
#endif
