// pcap_pkthdr

// bpf_u_int32 其实就是 u_int 类型


// pcap_next()方法执行后，pcap_pkthdr类型的指针指向抓包的信息
struct pcap_pkthdr {
	struct timeval ts;	/* time stamp 时间 */
	bpf_u_int32 caplen;	/* length of portion present 包的数据长度？？ */
	bpf_u_int32 len;	/* length this packet (off wire) 包的实际长度  */
};

//timeval结构
struct timeval{
　　long tv_sec;        /* seconds 1900之后的秒数 */
　　long tv_usec;      /* and microseconds */
};

struct pcap_stat {
	u_int ps_recv; /* number of packets received */
	u_int ps_drop; /* number of packets dropped */
	u_int ps_ifdrop; /* drops by interface XXX not yet supported */
};

// 非常重要的一个结构体
struct pcap{ 
	int fd; /* 文件描述字，实际就是 socket */
	/* 在 socket 上，可以使用 select() 和 poll() 等 I/O 复用类型函数 */
	int selectable_fd; 
	int snapshot; /* 用户期望的捕获数据包最大长度 */
	int linktype; /* 设备类型 */
	int tzoff;		/* 时区位置，实际上没有被使用 */
	int offset;	/* 边界对齐偏移量 */
	int break_loop; /* 强制从读数据包循环中跳出的标志 */
	struct pcap_sf sf; /* 数据包保存到文件的相关配置数据结构 */
	struct pcap_md md; /* 具体描述如下 */
	
	int bufsize; /* 读缓冲区的长度 */
	u_char buffer; /* 读缓冲区指针 */
	u_char *bp;
	int cc;
	u_char *pkt;
	/* 相关抽象操作的函数指针，最终指向特定操作系统的处理函数 */
	int	(*read_op)(pcap_t *, int cnt, pcap_handler, u_char *);
	int	(*setfilter_op)(pcap_t *, struct bpf_program *);
	int	(*set_datalink_op)(pcap_t *, int);
	int	(*getnonblock_op)(pcap_t *, char *);
	int	(*setnonblock_op)(pcap_t *, int, char *);
	int	(*stats_op)(pcap_t *, struct pcap_stat *);
	void (*close_op)(pcap_t *);
	/*如果 BPF 过滤代码不能在内核中执行,则将其保存并在用户空间执行 */
	struct bpf_program fcode; 
	/* 函数调用出错信息缓冲区 */
	char errbuf[PCAP_ERRBUF_SIZE + 1]; 
	
	/* 当前设备支持的、可更改的数据链路类型的个数 */
	int dlt_count;
	/* 可更改的数据链路类型号链表，在 linux 下没有使用 */
	int *dlt_list;
	/* 数据包自定义头部，对数据包捕获时间、捕获长度、真实长度进行描述 [pcap.h] */
	struct pcap_pkthdr pcap_header;	
};

/* 包含了捕获句柄的接口、状态、过滤信息  [pcap-int.h] */
struct pcap_md {
	/* 捕获状态结构  [pcap.h] */
	struct pcap_stat stat;  
	int use_bpf; /* 如果为1，则代表使用内核过滤*/ 
	u_long	TotPkts; 
	u_long	TotAccepted; /* 被接收数据包数目 */ 
	u_long	TotDrops;	/* 被丢弃数据包数目 */ 
	long	TotMissed;	/* 在过滤进行时被接口丢弃的数据包数目 */
	long	OrigMissed; /*在过滤进行前被接口丢弃的数据包数目*/
#ifdef linux
	int	sock_packet; /* 如果为 1，则代表使用 2.0 内核的 SOCK_PACKET 模式 */
	int	timeout;	/* pcap_open_live() 函数超时返回时间*/ 
	int	clear_promisc; /* 关闭时设置接口为非混杂模式 */ 
	int	cooked;		/* 使用 SOCK_DGRAM 类型 */
	int	lo_ifindex;	/* 回路设备索引号 */
	char *device;	/* 接口设备名称 */ 
	
	/* 以混杂模式打开 SOCK_PACKET 类型 socket 的 pcap_t 链表*/
	struct pcap *next;
#endif
};

