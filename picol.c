/* Tcl in ~ 500 lines of code by Salvatore antirez Sanfilippo. BSD licensed */
#include "picol.h"
#define CALLFRAME_SIZE 1024
#define COMMANDS_SIZE 4096

enum {PT_ESC, PT_STR, PT_CMD, PT_VAR, PT_SEP, PT_EOL, PT_EOF};
typedef void (*HTabNodeDestroyValueFunc) ( void* data );
typedef struct _HashTable HashTable;

typedef struct {
    char *text, *p;      // current text position
    char *start, *end;   // token start, token end
    int type;            // token type: PT_...
    int insidequote;     // True if inside " "
} PicolParser;

typedef struct {
    char* key;
    void* value;
} HTabNode;

struct _HashTable {
    int num_nodes;
    HashTable* parent;   // so we can chain hash tables (useful for callframes)
    HTabNode nodes[1];
};

typedef struct {
    PicolCmdFunc func;
    void *privdata;
} PicolCmd;

struct _PicolInterp {
    int level; // Level of nesting
    char *result;
    HashTable *callframe, *commands;
};

HashTable* htab_new( int size ) {
    HashTable* htab = (HashTable*) calloc( 1, sizeof(HashTable) + (size * sizeof(HTabNode)) );
    if( !htab ) return NULL;

    htab->num_nodes = size;
    return htab;
}

void htab_destroy( HashTable* htab, HTabNodeDestroyValueFunc destroy_data ) {
    int i;
    for( i = 0; i < htab->num_nodes; i++ ) {
        if( htab->nodes[i].key ) {
            free( htab->nodes[i].key );
            if( destroy_data && htab->nodes[i].value ) destroy_data( htab->nodes[i].value );
        }
    }

    free( htab );
    htab = NULL;
}

unsigned int htab_hash( HashTable* htab, char* k ) {
    unsigned int hash = 1;
    char* c;
    for( c = k; *c; c++ ) hash += (hash << *c) - *c;
    return hash % htab->num_nodes;
}

int htab_set( HashTable* htab, char* k, void* v, int overwrite ) {
    int hash = htab_hash( htab, k );
    char *key = htab->nodes[hash].key, *val = htab->nodes[hash].value;

    if( !key ) {
        htab->nodes[hash].key = strdup( k );
    } else {
        if( !overwrite || strcmp(key, k) != 0 ) return 0;
        if( val ) free( val );
    }

    htab->nodes[hash].value = v;
    return 1;
}

HTabNode* htab_find( HashTable* htab, char* key ) {
    int hash = htab_hash( htab, key );
    if( htab->nodes[hash].key != NULL ) return &htab->nodes[hash];
    return NULL;
}

static void picol_init_parser( PicolParser *p, char *text ) {
    p->text = p->p = text;
    p->start = p->end = 0;
    p->insidequote = 0;
    p->type = PT_EOL;
}

static int picol_parse_sep( PicolParser *p ) {
    p->start = p->p;
    while( isspace(*p->p) || (*p->p=='\\' && *(p->p+1)=='\n') ) p->p++;
    p->end = p->p-1;
    p->type = PT_SEP;
    return PICOL_OK;
}

static int picol_parse_eol( PicolParser *p ) {
    p->start = p->p;
    while( isspace(*p->p) || *p->p == ';' ) p->p++;
    p->end = p->p-1;
    p->type = PT_EOL;
    return PICOL_OK;
}

static int picol_parse_command( PicolParser *p ) {
    int level = 1;
    int blevel = 0;
    p->start = ++p->p; // skip the [
    while( *p->p ) {
        if( *p->p == '[' && blevel == 0 ) {
            level++;
        } else if( *p->p == ']' && blevel == 0 ) {
            if( !--level ) break;
        } else if( *p->p == '\\' ) {
            p->p++;
        } else if( *p->p == '{' ) {
            blevel++;
        } else if( *p->p == '}' ) {
            if( blevel != 0 ) blevel--;
        }
        p->p++;
    }
    p->end = p->p-1;
    p->type = PT_CMD;
    if( *p->p == ']' ) p->p++;
    return PICOL_OK;
}

#define is_alphanum( x ) (x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z') || (x >= '0' && x <= '9')
static int picol_parse_var( PicolParser *p ) {
    p->start = ++p->p; // skip the $
    while( is_alphanum(*p->p) || *p->p == '_' ) p->p++;

    p->end = p->p-1;
    if( p->start == p->p ) { // It's just a single char string "$"
        p->start = p->end;
        p->type = PT_STR;
    } else {
        p->type = PT_VAR;
    }
    return PICOL_OK;
}

static int picol_parse_brace( PicolParser *p ) {
    int level = 1;
    p->start = ++p->p; // skip the opening brace
    while(1) {
        if( p->p[0] && p->p[1] && *p->p == '\\' ) { // NOTE: here was p->len >= 2
            p->p++;
        } else if( *p->p == '\0' || *p->p == '}' ) {
            level--;
            if( level == 0 || *p->p == '\0' ) {
                p->end = p->p-1;
                if( *p->p ) p->p++; // Skip final closed brace
                p->type = PT_STR;
                return PICOL_OK;
            }
        } else if( *p->p == '{' ) {
            level++;
        }
        p->p++;
    }
    return PICOL_OK; // unreached
}

static int picol_parse_string( PicolParser *p ) {
    int newword = (p->type == PT_SEP || p->type == PT_EOL || p->type == PT_STR);
    if( newword && *p->p == '{' ) {
        return picol_parse_brace(p);
    } else if( newword && *p->p == '"' ) {
        p->insidequote = 1;
        p->p++; // skip the quote
    }
    p->start = p->p;
    while(1) {
        if( *p->p == '\0' ) {
            p->end = p->p-1;
            p->type = PT_ESC;
            return PICOL_OK;
        }
        switch( *p->p ) {
            case '\\':
                if( p->p[0] && p->p[1] ) p->p++; // NOTE: here was p->len >= 2
                break;
            case '$': case '[':
                p->end = p->p-1;
                p->type = PT_ESC;
                return PICOL_OK;
            case ' ': case '\t': case '\n': case '\r': case ';':
                if( !p->insidequote ) {
                    p->end = p->p-1;
                    p->type = PT_ESC;
                    return PICOL_OK;
                }
                break;
            case '"':
                if( p->insidequote ) {
                    p->end = p->p-1;
                    p->type = PT_ESC;
                    p->p++;
                    p->insidequote = 0;
                    return PICOL_OK;
                }
                break;
        }
        p->p++;
    }
    return PICOL_OK; // unreached
}

static int picol_parse_comment( PicolParser *p ) {
    char *lp = p->p;    // last p
    while( *p->p && (*p->p != '\n' || *lp == '\\') ) lp = p->p++;
    return PICOL_OK;
}

static int picol_get_token( PicolParser *p ) {
    while(1) {
        if( *p->p == '\0' ) {
            if( p->type != PT_EOL && p->type != PT_EOF ) p->type = PT_EOL;
            else p->type = PT_EOF;
            return PICOL_OK;
        }
        switch( *p->p ) {
            case ' ': case '\t': case '\r':
                if( p->insidequote ) return picol_parse_string(p);
                return picol_parse_sep(p);
            case '\n': case ';':
                if( p->insidequote ) return picol_parse_string(p);
                return picol_parse_eol(p);
            case '[':
                return picol_parse_command(p);
            case '$':
                return picol_parse_var(p);
            case '#':
                if( p->type == PT_EOL ) {
                    picol_parse_comment(p);
                    continue;
                }
            default:
                return picol_parse_string(p);
        }
    }
    return PICOL_OK; // unreached
}

static void picol_set_result( PicolInterp *i, char *s ) {
    free( i->result );
    i->result = strdup( s );
}

static PicolCmd *picol_get_command( PicolInterp *i, char *name ) {
    HTabNode* node = htab_find( i->commands, name );
    if( node ) return node->value;
    return NULL;
}

// ACTUAL COMMANDS!
static int picol_command_math( PicolInterp *i, int argc, char **argv, void *pd ) {
    char buf[64];
    int a, b, c;
    if( argc != 3 ) return picol_arity_err( i, argv[0] );
    a = atoi( argv[1] );
    b = atoi( argv[2] );
    if( argv[0][0] == '+' ) c = a+b;
    else if( argv[0][0] == '-' ) c = a-b;
    else if( argv[0][0] == '*' ) c = a*b;
    else if( argv[0][0] == '/' ) c = a/b;
    else if( argv[0][0] == '>' && argv[0][1] == '\0' ) c = a > b;
    else if( argv[0][0] == '>' && argv[0][1] == '=' ) c = a >= b;
    else if( argv[0][0] == '<' && argv[0][1] == '\0' ) c = a < b;
    else if( argv[0][0] == '<' && argv[0][1] == '=' ) c = a <= b;
    else if( argv[0][0] == '=' && argv[0][1] == '=' ) c = a == b;
    else if( argv[0][0] == '!' && argv[0][1] == '=' ) c = a != b;
    else c = 0; // I hate warnings
    snprintf( buf, 64, "%d", c );
    picol_set_result( i, buf );
    return PICOL_OK;
}

static int picol_command_set( PicolInterp *i, int argc, char **argv, void *pd ) {
    if( argc != 3) return picol_arity_err( i, argv[0] );
    if( picol_set_var(i, argv[1], argv[2]) != PICOL_OK ) return PICOL_ERR;
    picol_set_result( i, argv[2] );
    return PICOL_OK;
}

static int picol_command_puts( PicolInterp *i, int argc, char **argv, void *pd ) {
    if( argc != 2 ) return picol_arity_err( i, argv[0] );
    printf( "%s\n", argv[1] );
    return PICOL_OK;
}

static int picol_command_if( PicolInterp *i, int argc, char **argv, void *pd ) {
    int retcode;
    if( argc != 3 && argc != 5 ) return picol_arity_err( i, argv[0] );
    retcode = picol_eval( i, argv[1] );
    if( retcode != PICOL_OK ) return retcode;
    if( atoi(i->result) ) return picol_eval( i, argv[2] );
    else if( argc == 5 ) return picol_eval( i, argv[4] );
    return PICOL_OK;
}

static int picol_command_while( PicolInterp *i, int argc, char **argv, void *pd ) {
    if( argc != 3 ) return picol_arity_err( i, argv[0] );
    while(1) {
        int retcode = picol_eval( i, argv[1] );
        if( retcode != PICOL_OK ) return retcode;
        if( atoi(i->result) ) {
            retcode = picol_eval( i, argv[2] );
            if( retcode == PICOL_CONTINUE || retcode == PICOL_OK ) continue;
            else if( retcode == PICOL_BREAK ) return PICOL_OK;
            else return retcode;
        } else {
            return PICOL_OK;
        }
    }
}

static int picol_command_ret_codes( PicolInterp *i, int argc, char **argv, void *pd ) {
    if( argc != 1 ) return picol_arity_err(i,argv[0]);
    if( strcmp(argv[0], "break") == 0 ) return PICOL_BREAK;
    else if( strcmp(argv[0], "continue") == 0 ) return PICOL_CONTINUE;
    return PICOL_OK;
}

static void picol_drop_call_frame( PicolInterp *i ) {
    HashTable *cf = i->callframe;
    i->callframe = cf->parent;
    htab_destroy( cf, free );
}

static int picol_command_call_proc(PicolInterp *i, int argc, char **argv, void *pd) {
    char **x=pd, *alist=x[0], *body=x[1], *p=strdup(alist), *tofree;
    HashTable *cf = htab_new( CALLFRAME_SIZE );
    int arity = 0, done = 0, errcode = PICOL_OK;
    char errbuf[1024];
    cf->parent = i->callframe;
    i->callframe = cf;
    tofree = p;
    while( 1 ) {
        char *start = p;
        while( *p != ' ' && *p != '\0' ) p++;
        if( *p != '\0' && p == start ) {
            p++;
            continue;
        }
        if( p == start ) break;
        if( *p == '\0' ) done=1; else *p = '\0';
        if( ++arity > argc-1 ) goto arityerr;
        if( picol_set_var(i, start, argv[arity]) != PICOL_OK ) goto set_var_err;
        p++;
        if( done ) break;
    }
    free(tofree);
    if( arity != argc-1 ) goto arityerr;
    errcode = picol_eval( i, body );
    if( errcode == PICOL_RETURN ) errcode = PICOL_OK;
    picol_drop_call_frame( i ); // remove the called proc callframe
    return errcode;
arityerr:
    snprintf( errbuf, 1024, "Proc '%s' called with wrong arg num", argv[0] );
    picol_set_result( i, errbuf );
set_var_err:
    free( tofree );
    picol_drop_call_frame( i ); // remove the called proc callframe
    return PICOL_ERR;
}

static int picol_command_proc( PicolInterp *i, int argc, char **argv, void *pd ) {
    char **procdata = malloc(sizeof(char*)*2);
    if( argc != 4 ) return picol_arity_err( i, argv[0] );

    procdata[0] = strdup( argv[2] ); // arguments list
    procdata[1] = strdup( argv[3] ); // procedure body
    return picol_register_command( i, argv[1], picol_command_call_proc, procdata );
}

static int picol_command_return(PicolInterp *i, int argc, char **argv, void *pd) {
    if( argc != 1 && argc != 2 ) return picol_arity_err( i, argv[0] );
    picol_set_result( i, (argc == 2) ? argv[1] : "" );
    return PICOL_RETURN;
}

static void picol_register_core_commands( PicolInterp *i ) {
    int j;
    char *name[] = {"+","-","*","/",">",">=","<","<=","==","!=", NULL};
    for( j = 0; name[j]; j++ ) picol_register_command( i, name[j], picol_command_math, NULL );
    picol_register_command( i, "set", picol_command_set, NULL);
    picol_register_command( i, "puts", picol_command_puts, NULL);
    picol_register_command( i, "if", picol_command_if, NULL);
    picol_register_command( i, "while", picol_command_while, NULL);
    picol_register_command( i, "break", picol_command_ret_codes, NULL);
    picol_register_command( i, "continue", picol_command_ret_codes, NULL);
    picol_register_command( i, "proc", picol_command_proc, NULL);
    picol_register_command( i, "return", picol_command_return, NULL);
}

static void picol_destroy_command( void* cmd ){
    PicolCmd* c = cmd;
    if( c->privdata ) free( c->privdata );
    free( c );
}

// External API
PicolInterp* picol_interp_new() {
    PicolInterp *i = malloc(sizeof(PicolInterp));
    if( !i ) return NULL;
    i->level = 0;
    i->callframe = htab_new( CALLFRAME_SIZE );
    i->commands = htab_new( COMMANDS_SIZE );
    i->result = strdup("");
    picol_register_core_commands( i );
    return i;
}

void picol_interp_destroy( PicolInterp* i ) {
    if( i->result ) free( i->result );
    if( i->commands ) htab_destroy( i->commands, picol_destroy_command );
    while( i->callframe ) picol_drop_call_frame( i );
    free( i );
}

int picol_eval( PicolInterp *i, char *t ) {
    PicolParser p;
    int j, argc = 0, retcode = PICOL_OK;
    char errbuf[1024], **argv = NULL;
    picol_set_result( i, "" );
    picol_init_parser( &p, t );
    while( 1 ) {
        char *t;
        int tlen, prevtype = p.type;
        picol_get_token( &p );
        if( p.type == PT_EOF ) break;
        tlen = p.end - p.start + 1;
        if( tlen < 0 ) tlen = 0;

        t = malloc(tlen+1);
        memcpy(t, p.start, tlen);
        t[tlen] = '\0';
        if( p.type == PT_VAR ) {
            char *v = picol_get_var( i, t );
            if( !v ) {
                snprintf( errbuf, 1024, "No such variable '%s'", t );
                free( t );
                picol_set_result( i, errbuf );
                retcode = PICOL_ERR;
                goto err;
            }
            free( t );
            t = strdup( v );
        } else if( p.type == PT_CMD ) {
            retcode = picol_eval( i, t );
            free(t);
            if( retcode != PICOL_OK ) goto err;
            t = strdup( i->result );
        } else if( p.type == PT_ESC ) {
            // TODO: escape handling missing!
        } else if( p.type == PT_SEP ) {
            free(t);
            continue;
        }
        // We have a complete command + args. Call it!
        if( p.type == PT_EOL ) {
            free( t );
            if( argc ) {
                PicolCmd *c = picol_get_command( i, argv[0] );
                if( c == NULL) {
                    snprintf( errbuf, 1024, "No such command '%s'", argv[0] );
                    picol_set_result( i, errbuf );
                    retcode = PICOL_ERR;
                    goto err;
                }
                retcode = c->func( i, argc, argv, c->privdata );
                if( retcode != PICOL_OK ) goto err;
            }
            // Prepare for the next command
            for( j = 0; j < argc; j++ ) free(argv[j]);
            free(argv);
            argv = NULL;
            argc = 0;
            continue;
        }
        // We have a new token, append to the previous or as new arg?
        if( prevtype == PT_SEP || prevtype == PT_EOL ) {
            argv = realloc(argv, sizeof(char*)*(argc+1));
            argv[argc] = t;
            argc++;
        } else { // Interpolation
            int oldlen = strlen(argv[argc-1]), tlen = strlen(t);
            argv[argc-1] = realloc( argv[argc-1], oldlen + tlen + 1 );
            memcpy( argv[argc-1] + oldlen, t, tlen );
            argv[argc-1][oldlen+tlen] = '\0';
            free(t);
        }
    }
err:
    for( j = 0; j < argc; j++ ) free(argv[j]);
    free(argv);
    return retcode;
}

int picol_arity_err( PicolInterp *i, char *name ) {
    char buf[1024];
    snprintf( buf, 1024, "Wrong number of args for %s", name );
    picol_set_result( i, buf );
    return PICOL_ERR;
}

int picol_register_command( PicolInterp *i, char *name, PicolCmdFunc f, void *privdata ) {
    PicolCmd *c = malloc( sizeof(PicolCmd) );
    c->func = f;
    c->privdata = privdata;

    if( !htab_set(i->commands, name, c, 0) ) {
        char errbuf[1024];
        free( c );
        snprintf( errbuf, 1024, "Command '%s' already defined", name );
        picol_set_result( i, errbuf );
        return PICOL_ERR;
    }
    return PICOL_OK;
}

char *picol_get_var( PicolInterp *i, char *name ) {
    HTabNode* node = htab_find( i->callframe, name );
    if( node ) return node->value;
    return NULL;
}

int picol_set_var(PicolInterp *i, char *name, char *val) {
    char *var_dup = strdup(val);
    if( !htab_set(i->callframe, name, var_dup, 1) ) {
        free( var_dup );
        char errbuf[1024];
        snprintf( errbuf, 1024, "Couldn't set variable '%s'", name );
        picol_set_result( i, errbuf );
        return PICOL_ERR;
    }
    return PICOL_OK;
}

char *picol_get_result( PicolInterp *i ) {
    return i->result;
}
