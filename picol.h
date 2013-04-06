#ifndef PICOL_INCLUDED
#define PICOL_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

typedef struct _PicolInterp PicolInterp;
typedef int (*PicolCmdFunc) ( PicolInterp *i, int argc, char **argv, void *privdata );

enum{ PICOL_OK, PICOL_ERR, PICOL_RETURN, PICOL_BREAK, PICOL_CONTINUE };

PicolInterp *picol_interp_new();
int picol_eval( PicolInterp *i, char *t );

int picol_register_command( PicolInterp *i, char *name, PicolCmdFunc f, void *privdata );
int picol_arity_err( PicolInterp *i, char *name );

int picol_set_var( PicolInterp *i, char *name, char *val );
char *picol_get_var( PicolInterp *i, char *name );
char *picol_get_result( PicolInterp *i );

#endif
