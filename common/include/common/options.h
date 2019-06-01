// SPDX-License-Identifier: GPL-2.0

#ifndef _OPTIONS_H
#define _OPTIONS_H

#include <getopt.h>
#include <stdio.h>

static void usage(char *argv[], const char *doc, const struct option long_options[], const char *long_options_descriptions[])
{
    int i;
    printf("%s\n", doc);
    printf("Usage: %s [options]\n\n", argv[0]);
    printf("Options:\n");

    for (i = 0; long_options[i].name != 0; i++)
    {
        printf(" -%c|--%-12s %s\n", long_options[i].val, long_options[i].name,
               long_options_descriptions[i]);
    }
    printf("\n");
}

/*
    This is needed due to getopt's optional_argument parsing:
    https://stackoverflow.com/questions/1052746/getopt-does-not-parse-optional-arguments-to-parameters
*/
bool handle_optional_argument(int argc, char **argv)
{
    if (!optarg && optind < argc && NULL != argv[optind] && '\0' != argv[optind][0] && '-' != argv[optind][0])
    {
        return true;
    }
    return false;
}

#endif // _OPTIONS_H