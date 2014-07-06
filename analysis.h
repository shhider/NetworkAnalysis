/*analysis.h*/

typedef struct _net5set
{
    u_int       sip;
    u_short     sport;
    u_int       dip;
    u_short     dport;
    u_char      protocol;
}net5set;

typedef struct _anaysis_link_node
{
    net5set     aln_5set;
    long        aln_ctime;
    long        aln_dtime;
    int         aln_upl_size;
    int         aln_downl_size;
    struct _anaysis_link_node *next;
}anaysis_link_node, *p_analysis_link;

typedef struct _hash_link_node
{
    net5set     hln_5set;
    long        hln_ctime;
    long        hln_dtime;
    int         hln_upl_size;
    int         hln_downl_size;
    u_char      hln_status;
#define CLOSED      0x00;

#define UNDEFINED   0xff;
    struct _hash_link_node *next;
}hash_link_node, *p_hash_link;


#define IPTOSBUFFERS    12
static char *iptos(bpf_u_int32 in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

char *long2time(long ltime)
{
    time_t t;
    struct tm *p;
    static char s[100];

    t = ltime;
    p=gmtime(&t);

    strftime(s, sizeof(s), "%Y-%m-%d %H:%M:%S", p);
    return s;
}
