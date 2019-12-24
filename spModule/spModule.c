#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <net/ip.h>
#include <uapi/linux/netfilter.h>
#include <uapi/linux/netfilter_ipv4.h>

#define NIPQUAD(addr) \
	((unsigned char*)&addr)[0], \
	((unsigned char*)&addr)[1], \
	((unsigned char*)&addr)[2], \
	((unsigned char*)&addr)[3]

#define ENTRY_NAME "spModProc"
static struct proc_dir_entry *proc_entry;
unsigned short int forwardingPort = 0;

static int proc_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "[ MOD-LOG ] Proc Opened.\n");
	if (1 != htonl(1)) printk(KERN_INFO "[ MOD-LOG ]   Little Endian\n");
	else printk(KERN_INFO "[MOD-LOG]   Big Endian\n");
	return 0;
}
static ssize_t proc_write(struct file *file, const char __user *user_buffer, size_t count, loff_t *ppos)
{	sscanf(user_buffer, "%hu", &forwardingPort);
	printk(KERN_INFO "[ MOD-LOG ] Proc Wrote: %hu\n", forwardingPort);
	return count;
}
static const struct file_operations proc_fops = {
	.owner = THIS_MODULE,
	.open = proc_open,
	.write = proc_write,
};

struct iphdr *IPH;
struct tcphdr *TCPH;
unsigned short int sport;
unsigned short int dport;
static int tag = 0;
static unsigned int hook_pre(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	IPH = ip_hdr(skb);
	TCPH = tcp_hdr(skb);
	sport = ntohs((unsigned short int)TCPH->source);
	dport = ntohs((unsigned short int)TCPH->dest);

	tag ++;
	printk(KERN_INFO "[ MOD-LOG ] <%d>PreHook >> syn:%hu ack:%hu fin:%hu\n", tag, TCPH->syn, TCPH->ack, TCPH->fin);
	printk(KERN_INFO "[ MOD-LOG ]   sIP: %d.%d.%d.%d <%hu>\n", NIPQUAD(IPH->saddr), sport);
	printk(KERN_INFO "[ MOD-LOG ]   dIP: %d.%d.%d.%d <%hu>\n", NIPQUAD(IPH->daddr), dport);

	if (dport == forwardingPort)
	{
		printk("[ MOD-LOG ]     Forwarding #%hu >>\n", forwardingPort);
		IPH->saddr = in_aton("131.1.1.0");
		IPH->daddr = in_aton("123.1.1.0");
		TCPH->dest = htons((unsigned short int)7777);
		dport = ntohs((unsigned short int)TCPH->dest);
		printk(KERN_INFO "[ MOD-LOG ]       sIP: %d.%d.%d.%d <%hu>\n", NIPQUAD(IPH->saddr), sport);
		printk(KERN_INFO "[ MOD-LOG ]       dIP: %d.%d.%d.%d <%hu>\n", NIPQUAD(IPH->daddr), dport);

		// Update checksum
		TCPH->check = 0;
		skb->csum = csum_partial((unsigned char*)TCPH, ntohs(IPH->tot_len) - ip_hdrlen(skb), 0);
		TCPH->check = csum_tcpudp_magic(IPH->saddr, IPH->daddr, ntohs(IPH->tot_len) - ip_hdrlen(skb), IPH->protocol, skb->csum);
		IPH->check = 0;
		IPH->check = ip_fast_csum(IPH, IPH->ihl);

		skb->ip_summed = CHECKSUM_NONE;
		skb->pkt_type = PACKET_OTHERHOST;
	}

	return NF_ACCEPT;
}
static unsigned int hook_post(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	IPH = ip_hdr(skb);
	TCPH = tcp_hdr(skb);
	sport = ntohs((unsigned short int)TCPH->source);
	dport = ntohs((unsigned short int)TCPH->dest);

	tag ++;
	printk(KERN_INFO "[ MOD-LOG ] <%d>PostHook >> syn:%hu ack:%hu fin:%hu\n", tag, TCPH->syn, TCPH->ack, TCPH->fin);
	printk(KERN_INFO "[ MOD-LOG ]   sIP: %d.%d.%d.%d <%hu>\n", NIPQUAD(IPH->saddr), sport);
	printk(KERN_INFO "[ MOD-LOG ]   dIP: %d.%d.%d.%d <%hu>\n", NIPQUAD(IPH->daddr), dport);
	return NF_ACCEPT;
}


static unsigned int hook_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	IPH = ip_hdr(skb);
	TCPH = tcp_hdr(skb);
	sport = ntohs((unsigned short int)TCPH->source);
	dport = ntohs((unsigned short int)TCPH->dest);
	tag ++;
	printk(KERN_INFO "[ MOD-LOG ] <%d>OutHook >> syn:%hu ack:%hu fin:%hu\n", tag, TCPH->syn, TCPH->ack, TCPH->fin);
	printk(KERN_INFO "[ MOD-LOG ]   sIP: %d.%d.%d.%d <%hu>\n", NIPQUAD(IPH->saddr), sport);
	printk(KERN_INFO "[ MOD-LOG ]   dIP: %d.%d.%d.%d <%hu>\n", NIPQUAD(IPH->daddr), dport);
	return NF_ACCEPT;
}
static unsigned int hook_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	IPH = ip_hdr(skb);
	TCPH = tcp_hdr(skb);
	sport = ntohs((unsigned short int)TCPH->source);
	dport = ntohs((unsigned short int)TCPH->dest);
	tag ++;
	printk(KERN_INFO "[ MOD-LOG ] <%d>InHook >> syn:%hu ack:%hu fin:%hu\n", tag, TCPH->syn, TCPH->ack, TCPH->fin);
	printk(KERN_INFO "[ MOD-LOG ]   sIP: %d.%d.%d.%d <%hu>\n", NIPQUAD(IPH->saddr), sport);
	printk(KERN_INFO "[ MOD-LOG ]   dIP: %d.%d.%d.%d <%hu>\n", NIPQUAD(IPH->daddr), dport);
	return NF_ACCEPT;
}
static unsigned int hook_fwrd(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	IPH = ip_hdr(skb);
	TCPH = tcp_hdr(skb);
	sport = ntohs((unsigned short int)TCPH->source);
	dport = ntohs((unsigned short int)TCPH->dest);
	tag ++;
	printk(KERN_INFO "[ MOD-LOG ] <%d>FowardHook >> syn:%hu ack:%hu fin:%hu\n", tag, TCPH->syn, TCPH->ack, TCPH->fin);
	printk(KERN_INFO "[ MOD-LOG ]   sIP: %d.%d.%d.%d <%hu>\n", NIPQUAD(IPH->saddr), sport);
	printk(KERN_INFO "[ MOD-LOG ]   dIP: %d.%d.%d.%d <%hu>\n", NIPQUAD(IPH->daddr), dport);
	return NF_ACCEPT;
}
static struct nf_hook_ops ops_pre;
static struct nf_hook_ops ops_post;
static struct nf_hook_ops ops_out;
static struct nf_hook_ops ops_in;
static struct nf_hook_ops ops_fwrd;

static int __init mod_init(void)
{
	// Hook: Pre Routing
	ops_pre.hook = hook_pre;
	ops_pre.pf = PF_INET;
	ops_pre.hooknum = NF_INET_PRE_ROUTING;
	ops_pre.priority = NF_IP_PRI_FIRST;
	// Hook: Post Routing
	ops_post.hook = hook_post;
	ops_post.pf = PF_INET;
	ops_post.hooknum= NF_INET_POST_ROUTING;
	ops_post.priority = NF_IP_PRI_FIRST;
	// Hook: Local Out
	ops_out.hook = hook_out;
	ops_out.pf = PF_INET;
	ops_out.hooknum = NF_INET_LOCAL_OUT;
	ops_out.priority = NF_IP_PRI_FIRST;
	// Hook: Local In
	ops_in.hook = hook_in;
	ops_in.pf = PF_INET;
	ops_in.hooknum = NF_INET_LOCAL_IN;
	ops_in.priority = NF_IP_PRI_FIRST;
	// Hook: Forward
	ops_fwrd.hook = hook_fwrd;
	ops_fwrd.pf = PF_INET;
	ops_fwrd.hooknum = NF_INET_FORWARD;
	ops_fwrd.priority = NF_IP_PRI_FIRST;

	// Add Proc
	proc_entry = proc_create(ENTRY_NAME, 0755, NULL, &proc_fops);
	printk(KERN_INFO "[ MOD-LOG ] Module Loaded.\n");

	// Register hooks
	nf_register_hook(&ops_pre);
	nf_register_hook(&ops_post);
	nf_register_hook(&ops_out);
	nf_register_hook(&ops_in);
	nf_register_hook(&ops_fwrd);

	return 0;
}

static void __exit mod_exit(void)
{
	// Remove Proc
	proc_remove(proc_entry);
	printk(KERN_INFO "[ MOD-LOG ] Module Exited.");

	// Unregister hooks
	nf_unregister_hook(&ops_pre);
	nf_unregister_hook(&ops_post);
	nf_unregister_hook(&ops_out);
	nf_unregister_hook(&ops_in);
	nf_unregister_hook(&ops_fwrd);
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR("Team 7");
MODULE_DESCRIPTION("SP Mod: Netfilter");
MODULE_LICENSE("GLP");
MODULE_VERSION("0.0");

