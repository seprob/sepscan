/* SEPSCAN (SEProb's SCANner) - is a ordinary port scanner
 * Author: Bartlomiej "seprob" Korpala
 * Information about author: http://seprob.damned.pl/
 * E-mail: seprob@poczta.fm
 * 
 * Standard compilation: gcc sepscan.c -o sepscan */

#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>

extern int h_errno;  /* Variable in which gethostbyname() function stores information about errors*/

/* error_errno() function give contents of error based on value attributed errno variable and finishes program */
void error_errno(const char *what);

/* error_h_errno() function give contents of error based on value attributed h_errno variable and finishes program */
void error_h_errno(const char *what);

/* error_none() function inform about error and finishes program */
void error_none(const char *what);

main(int argc, char *argv[])
{
   int sd;                      /* Socket descriptor */
   int port;                    /* Number of scanning port */
   int help_v;                  /* Hel variable */
   char *n_addr;                /* Host address */
   struct sockaddr_in in_addr;  /* Structure for fulfillment */
   struct servent *ss;          /* Structure included information from /etc/services file */
   struct hostent *sh;          /* Structure included information from gethostbyname() function */
   int port_tab[26208];         /* Table in which are stored values saying or port is active */
   char buf_conn[128];          /* Buffer for data get after telnet connect on give port */
   time_t now, now_two;         /* Wanted times dor account of period of scanning */

   if (argc == 1)
     error_none("Bad syntax. More you will get taking davantage --help option of program");
   else if (argc == 2)
     {
   if (!strcmp(argv[1], "--help"))
     {
        printf("Syntax: %s [Network Address]\n", argv[0]);
        printf("        %s --help                           (Information about usage of scanner)\n", argv[0]);
        printf("        %s --about                          (Information about program)\n", argv[0]);
        printf("        %s --more [Network Address]         (Give more information about scanning host)\n", argv[0]);
        printf("        %s --telnet-conn [Network Address]  (Display information which are gotted after telnet connect with active ports\n", argv[0]);
        exit(0);
     }
       else if (!strcmp(argv[1], "--about"))
     {
        printf("SepScan (Seprob's Scanner) is a network scanner writed by seprob [http://seprob.damned.pl/]\n");
        exit(0);
     }
   else
     sh = gethostbyname(argv[1]);
     }
   else if (argc == 3)
     {
   if (!strcmp(argv[1], "--more"))
     sh = gethostbyname(argv[2]);
   else if (!strcmp(argv[1], "--telnet-conn"))
     sh = gethostbyname(argv[2]);
   else
     error_none("Bad syntax. More you will get taking davantage --help option of program\n");
     }
   else if (argc = 4)
     {
   if (!strcmp(argv[1], "--more") && !strcmp(argv[2], "--telnet-conn"))
     sh = gethostbyname(argv[3]);
   else if (!strcmp(argv[1], "--telnet-conn") && !strcmp(argv[2], "--more"))
     sh = gethostbyname(argv[3]);
   else
     error_none("Bad syntax. More you will get taking davantage --help option of program\n");
     }
   else
     error_none("Bad syntax. More you will get taking davantage --help option of program");


   if (sh == NULL)
     error_h_errno("GETHOSTBYNAME");

   n_addr = inet_ntoa(*(struct in_addr *)sh->h_addr_list[0]);

   printf("SepScan - Seprob's Scanner by seprob [http://seprob.damned.pl/]\n");
   printf("\n");

   time(&now);  /* Get time from 1th February 1970 */

   memset(&port_tab, 0, sizeof(port_tab));

   /* Beginning of loop which checks all ports number */
   for (port = 1; port <= 26208; port++)
     {
   memset(&in_addr, 0, sizeof(in_addr));   /* Fulfillment zeros of addr structure */
   in_addr.sin_family = PF_INET;           /* PF_INET familly address */
   in_addr.sin_port = htons(port);         /* Convert from host byte order to network byte order */

   help_v = inet_aton(n_addr, &in_addr.sin_addr);  /* Attribution IP address */

   if (help_v == 0)
     error_none("Bad address");

   sd = socket(PF_INET, SOCK_STREAM, 0);  /* Creation of new socket */

   if (sd == -1)
     error_errno("SOCKET");

   help_v = connect(sd, (struct sockaddr *)&in_addr, sizeof(in_addr));

   if (help_v != -1)
     {
        port_tab[port] = 1;  /* Give port is active */

        ss = getservbyport(htons(port), "tcp");

        if (ss != NULL)
          printf("%s/%d/%s\n", ss->s_name, htons(ss->s_port), ss->s_proto);
        else
          printf("unknown/%d/tcp\n", port);
     }

   close(sd);
     }

   if (argc == 3 || argc == 4)
     {
   if (!strcmp(argv[1], "--more") || !strcmp(argv[2], "--more"))
     {
        printf("\n");
        printf("Official name of host: %s\n", sh->h_name);
        printf("Type of host address: %s\n", sh->h_addrtype == PF_INET ? "PF_INET" : "PF_INET6");

        printf("Aliases:\n");
        for (help_v = 0; sh->h_aliases[help_v] != 0; help_v++)
          printf("%s\n", sh->h_aliases[help_v]);

        printf("List of address:\n");
        for (help_v = 0; sh->h_addr_list[help_v] != 0; help_v++)
          printf("%s\n", inet_ntoa(*(struct in_addr *)sh->h_addr_list[0]));
     }

   if (!strcmp(argv[1], "--telnet-conn") || !strcmp(argv[2], "--telnet-conn"))
     {
        printf("\n");
        memset(buf_conn, '\0', sizeof(buf_conn));

        for (port = 1; port < 26208; port++)
          {
        if (port_tab[port] == 1)
          {
             memset(&in_addr, 0, sizeof(in_addr));
             in_addr.sin_family = PF_INET;
             in_addr.sin_port = htons(port);
             inet_aton(n_addr, &in_addr.sin_addr);

             sd = socket(PF_INET, SOCK_STREAM, 0);

             if (sd == -1)
          error_errno("SOCKET");

             help_v = connect(sd, (struct sockaddr *)&in_addr, sizeof(in_addr));

             if (help_v != -1)
          {
             help_v = read(sd, &buf_conn, sizeof(buf_conn));

             if (help_v == -1)
               error_errno("READ");

             printf("After telnet connect on %d port I have received following information:\n", port);
             printf("%s\n", buf_conn);
             printf("\n");

             memset(buf_conn, '\0', sizeof(buf_conn));
          }
          }
          }
     }
     }

   time(&now_two);

   printf("\n");
   printf("Time of scanning: %.2f\n", difftime(now_two, now));
   printf("Scanned %d ports on host %s\n", port, n_addr);

   return 0;
}

void error_errno(const char *what)
{
   fprintf(stderr, "%s: %s\n", what, strerror(errno));
   exit(1);
}

void error_h_errno(const char *what)
{
   fprintf(stderr, "%s: %s\n", what, hstrerror(h_errno));
   exit(1);
}

void error_none(const char *what)
{
   fprintf(stderr, "ERROR: %s\n", what);
   exit(1);
}
