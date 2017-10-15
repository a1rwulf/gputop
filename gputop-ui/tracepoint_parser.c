#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

struct tracepoint {
    struct {
        bool is_signed;
        int offset;
        int size;
        char name[80];
    } fields[20];
    int n_fields;
};

union value {
    char *string;
    int integer;
};

struct context {
    struct tracepoint *tp;
    char *buffer;
    size_t len;
    int pos;
};

#define YY_CTX_LOCAL
#define YY_CTX_MEMBERS struct context ctx;
#define YYSTYPE union value
#define YY_PARSE(T) static T
//#define YY_DEBUG

#include "tracepoint_format.leg.c"

int
main(int argc, char *argv[])
{
    struct tracepoint tp;
    yycontext ctx;
    memset(&tp, 0, sizeof(tp));
    memset(&ctx, 0, sizeof(ctx));

    ctx.ctx.tp = &tp;
    yyparse(&ctx);

    for (int i = 0; i < tp.n_fields; i++) {
        printf("%s offset=%i size=%i\n", tp.fields[i].name,
               tp.fields[i].offset, tp.fields[i].size);
    }

    return 0;
}
