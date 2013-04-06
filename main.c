#include "picol.h"

//TODO: add linenoise to the shell
int main( int argc, char **argv ) {
    PicolInterp *interp = picol_interp_new();
    if( argc == 1 ) {
        while( 1 ) {
            char clibuf[1024], *result;
            int retcode;
            printf( "picol> " );
            fflush( stdout );
            if( fgets(clibuf,1024,stdin) == NULL ) return 0;
            retcode = picol_eval( interp, clibuf );
            result = picol_get_result( interp );
            if( result[0] != '\0' ) printf( "[%d] %s\n", retcode, result );
        }
    } else if( argc == 2 ) {
        char buf[1024*16], *result;
        FILE *fp = fopen( argv[1],"r" );
        if( !fp ) {
            perror("open");
            exit(1);
        }
        buf[ fread(buf, 1, 1024*16, fp) ] = '\0';
        fclose(fp);

        if( picol_eval(interp, buf) != PICOL_OK ) {
          result = picol_get_result( interp );
          printf( "%s\n", result );
        }

    }

    picol_interp_destroy( interp );
    return 0;
}
