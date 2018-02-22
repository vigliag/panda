#pragma once
#include <string>
#include <sstream>
#include <dirent.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <sys/stat.h>

struct SearchInfo {
    std::string name;
    std::string buffer;
    uint32_t contextbytes = 0;
};


static std::vector<std::string> listFiles(const std::string& dirname){
    std::vector<std::string> res;

    DIR *dir = opendir(dirname.c_str());
    if (dir == NULL) {
        perror("unable to read contents of dir");
        return res;
    }

    /* print all the files and directories within directory */
    struct dirent *ent;
    while ((ent = readdir (dir)) != NULL) {
        if(ent->d_type == DT_REG){
            res.push_back(ent->d_name);
        } else {
            std::cerr << "excluding non-regular file " << ent->d_name << std::endl;
        }
    }

    closedir (dir);
    return res;
}

class SearchManager{
public:
    SearchManager(size_t CHUNK_LEN, size_t NCHUNKS):
    CHUNK_LEN(CHUNK_LEN), NCHUNKS(NCHUNKS) {

    }

    SearchManager(){}

    const size_t CHUNK_LEN = 8;
    const size_t NCHUNKS = 10;
    std::vector<SearchInfo> searches;

    void addChunks(const std::string& raw_search, const std::string& name){
        size_t raw_search_len = raw_search.length();

        for(size_t start=0; start < raw_search_len && start < CHUNK_LEN * NCHUNKS; start += CHUNK_LEN){
            SearchInfo si;
            si.buffer = raw_search.substr(start, CHUNK_LEN);
            si.name = name;
            si.name.append("+");
            si.name.append(std::to_string(start));

            //add context if its a single chunk
            if(raw_search_len < CHUNK_LEN){
                si.contextbytes = 256;
            }

            std::cout << si.name << " " << si.buffer.length() << " ";
            for(size_t j=0; j< si.buffer.length(); ++j){
                printf("%02x", (unsigned char) si.buffer[j]);
            }
            std::cout << std::endl;
            //added_count++;
            searches.push_back(si);
        }
    }

    bool readFile(const std::string& filename){
        std::ifstream filesearch_input(filename);
        std::stringstream sstream;
        sstream << filesearch_input.rdbuf();
        filesearch_input.tellg();
        if(filesearch_input.tellg() <= 0){
            fprintf(stderr, "Unable to read the file %s\n", filename.c_str());
            return false;
        }

        std::cout << "Added file " << filename << std::endl;
        std::string raw_search = sstream.str();

        //remove trailing return
        if(raw_search.back() == '\n')
            raw_search.pop_back();

        addChunks(raw_search, filename);
        return true;
    }

    void readFileList(const std::string& filelist_file){
        struct stat path_stat;
        stat(filelist_file.c_str(), &path_stat);

        if(S_ISREG(path_stat.st_mode)){
            std::cout << "reading from file list" << std::endl;
            std::ifstream filelist_input(filelist_file);
            for(std::string filename; getline(filelist_input, filename);){
                readFile(filename);
            }
        } else if(S_ISDIR(path_stat.st_mode)){
            std::cout << "collecting from folder" << std::endl;
            for(const std::string& filename : listFiles(filelist_file)){
                std::stringstream completeName;
                completeName << filelist_file << "/" << filename;
                readFile(completeName.str());
            }
        }
    }
};
