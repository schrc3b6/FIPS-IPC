#include <hs/hs_common.h>
#include <hs_compile.h>
#include <simplefail2ban.h>

int init_hs() {
  hs_platform_info_t *platform_info;
  hs_compile_error_t *compile_error;
  const char *const regexes[] = {server.config.regex_rate_limit, IP4_REGEX,
                                 IP6_REGEX};
  // HS_FLAG_SOM_LEFTMOST is used for ip matching to get left and right
  // boundaries of the match
  const unsigned int flags[] = {HS_FLAG_SINGLEMATCH, HS_FLAG_SOM_LEFTMOST,
                                HS_FLAG_SOM_LEFTMOST};
  const unsigned int ids[] = {RATE_LIMIT_REGEX_ID, IP4_REGEX_ID, IP6_REGEX_ID};

  if ((platform_info = (hs_platform_info_t *)calloc(sizeof(hs_platform_info_t),
                                                    1)) == NULL) {
    perror("calloc failed");
  }

  else if (hs_populate_platform(platform_info) != HS_SUCCESS) {
    fprintf(stderr, "hs_populate_platform failed\n");
    free(platform_info);
    platform_info = NULL;
  }

  if (hs_compile_multi(regexes, flags, ids, 3, HS_MODE_BLOCK, platform_info,
                       &server.database, &compile_error) != HS_SUCCESS) {
    fprintf(stderr, "hyperscan compilation failed with error code %d, %s\n",
            compile_error->expression, compile_error->message);
    hs_free_compile_error(compile_error);
    exit(EXIT_FAILURE);
  }

  if (platform_info != NULL) {
    free(platform_info);
    platform_info = NULL;
  }
  return 0;
}
