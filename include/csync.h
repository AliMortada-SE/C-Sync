#pragma once
#ifndef CSYNC_H
#define CSYNC_H

#include <vector>
#include <string>
#include <fstream>
#include <optional>
#include <unordered_map>
#include <cstdint>
#include <filesystem>
#include "wirelink.h"

namespace fs = std::filesystem;
class CSync{
    public:
    struct FileEntry{
        std::string name;
        std::string path;
        std::string hash;
        std::vector<uint8_t> data;
        bool update = 0;
    };

    bool init();
    bool open(uint16_t port);
    bool setup(std::string projectName);
    
    std::vector<uint8_t>   readFile(const std::string& path);
    std::vector<FileEntry> readLocal(const fs::path& dir);
    std::vector<FileEntry> readRemote();
    std::vector<FileEntry> compare(std::vector<FileEntry> local, std::vector<FileEntry> remote);
    
    bool updateFile(FileEntry file);
    bool upStream(std::vector<FileEntry> files);
    private:
    
};

#endif