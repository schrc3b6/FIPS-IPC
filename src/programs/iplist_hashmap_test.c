#include <ip_hashtable.h>
#include <ip_llist.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

int main(void){

    // test ip_hashtable
    
    static struct ip_hashtable_t * htable;
    int retval;
    int retval2;
    int retval6;

    char ip_test[INET_ADDRSTRLEN] = "10.3.10.1";

    char ip_test2[INET_ADDRSTRLEN] = "10.3.10.2";

    char ip6_test[INET6_ADDRSTRLEN] = "2001:9e8:f6b5:c00:e45e:af94:69cd:8d1a";

    // Init hashtable for tracking of logged ip addresses
	if((retval = ip_hashtable_init(&htable)) < 0)
	{
		fprintf(stderr,"ip_hashtable_init failed with error code %d\n", retval);
		exit(EXIT_FAILURE);
	}

    retval = ip_hashtable_insert(htable, ip_test, AF_INET);
    retval = ip_hashtable_insert(htable, ip_test, AF_INET);
    retval = ip_hashtable_insert(htable, ip_test, AF_INET);

    retval6 = ip_hashtable_insert(htable, ip6_test, AF_INET6);
    retval6 = ip_hashtable_insert(htable, ip6_test, AF_INET6);

    printf("retval6: %d\n", retval6);
    


    retval = ip_hashtable_set(htable, ip_test, AF_INET, 21);
    retval = ip_hashtable_remove(htable, ip_test, AF_INET);
    retval6 = ip_hashtable_remove(htable, ip6_test, AF_INET6);






    printf("retval: %d\n", retval);
    printf("retval6: %d\n", retval6);





    if(htable != NULL)
	{
		if((retval = ip_hashtable_destroy(&htable)) < 0)
		{
			fprintf(stderr, "ip_hashtable_destroy failed with error code %d\n", retval);
		}
	}
    

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // test ip_llist

    // static struct ip_llist_t * banned_list;
    // int retval;
    // char ip_test[INET_ADDRSTRLEN] = "10.3.10.11";
    // char ip6_test[INET6_ADDRSTRLEN] = "2001:9e8:f6b5:c00:e45e:af94:69cd:8d1a";
    // time_t ts = time(NULL);
    // struct ip_listnode_t *iterator, * prev;


    // if((retval = ip_llist_init(&banned_list)) < 0)
	// {
	// 	fprintf(stderr,"ip_llist_init failed with error code %d\n", retval);
	// 	exit(EXIT_FAILURE);
	// }

    // if((retval = ip_llist_push(banned_list, ip6_test, &ts, AF_INET6)) < 0){

    //     fprintf(stderr, "ip_llist_push failed with error code %d\n", retval);
    // };


    // iterator = banned_list->head;
    // if(iterator != NULL){
    //     printf("ip_string: %s\n", (char *)(iterator->key));
    // }

    // if(banned_list != NULL)
	// {
	// 	if((retval = ip_llist_destroy(&banned_list)) != IP_LLIST_SUCCESS)
	// 	{
	// 		fprintf(stderr, "ip_llist_destroy failed with error code %d\n", retval);
	// 	}
	// }


    return 0;
}
