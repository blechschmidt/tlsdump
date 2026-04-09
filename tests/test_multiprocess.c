#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <curl/curl.h>

static size_t discard(void *ptr, size_t size, size_t nmemb, void *data) {
    (void)ptr; (void)data;
    return size * nmemb;
}

static void do_request(const char *url) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "curl_easy_init failed\n");
        return;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform: %s\n", curl_easy_strerror(res));
    }
    curl_easy_cleanup(curl);
}

static void *thread_func(void *arg) {
    do_request((const char *)arg);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s --fork|--thread <url>\n", argv[0]);
        return 1;
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);

    if (strcmp(argv[1], "--fork") == 0) {
        /* Use pipes to sequence requests and keep both processes alive:
         * 1. Child makes its request first
         * 2. Child signals parent via pipe
         * 3. Parent makes its request
         * 4. Parent signals child to exit via pipe
         * This avoids TCP timeouts from pausing during memory search
         * and keeps the child alive so its memory can be scanned. */
        int p2c[2], c2p[2];
        pipe(p2c);
        pipe(c2p);

        pid_t child = fork();
        if (child == 0) {
            close(p2c[1]);
            close(c2p[0]);
            do_request(argv[2]);
            /* Signal parent: child request done */
            write(c2p[1], "x", 1);
            close(c2p[1]);
            /* Wait for parent to finish */
            char buf;
            read(p2c[0], &buf, 1);
            close(p2c[0]);
            curl_global_cleanup();
            _exit(0);
        }
        close(p2c[0]);
        close(c2p[1]);
        /* Wait for child to finish its request */
        char buf;
        read(c2p[0], &buf, 1);
        close(c2p[0]);
        /* Parent makes its request */
        do_request(argv[2]);
        /* Signal child to exit */
        close(p2c[1]);
        waitpid(child, NULL, 0);
    } else if (strcmp(argv[1], "--thread") == 0) {
        pthread_t tid;
        pthread_create(&tid, NULL, thread_func, argv[2]);
        do_request(argv[2]);
        pthread_join(tid, NULL);
    } else {
        fprintf(stderr, "Unknown mode: %s\n", argv[1]);
        curl_global_cleanup();
        return 1;
    }

    curl_global_cleanup();
    return 0;
}
