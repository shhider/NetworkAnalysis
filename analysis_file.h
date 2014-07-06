// analysis_file.h
void analysis_file(char *filename)
{
    FILE *fp = fopen(filename, 'r');
    if(fp == NULL)
    {
        printf("File don't exist!\n");
        return 0;
    }

}
