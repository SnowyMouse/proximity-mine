# SPDX-License-Identifier: GPL-3.0-only

# Require at least version 3.12
cmake_minimum_required(VERSION 3.12)

# Use C99
set(CMAKE_C_STANDARD 99)

# Project name - You should change this if you're making a fork
project(ProximityMine
    VERSION 0.1.0
    DESCRIPTION "Implode your maps"
    LANGUAGES C
)

add_executable(proximity-mine
    src/main.c
)
