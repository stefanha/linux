#ifndef ISCSI_AUTH_H
#define ISCSI_AUTH_H

#define TEXT_LEN 	4096
#define AUTH_CLIENT	1
#define AUTH_SERVER	2
#define DECIMAL		0
#define HEX		1

extern void convert_null_to_semi(char *, int);
extern int extract_param(const char *, const char *, unsigned int, char *,
		unsigned char *);

#endif /* ISCSI_AUTH_H */
