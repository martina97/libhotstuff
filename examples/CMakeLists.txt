# Copyright (c) 2019 Ted Yin
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Aggiungi tutti i file .h dalla cartella "include"
file(GLOB HEADER_FILES "../include/*.h")
# Aggiungi la directory "include" ai percorsi di inclusione
include_directories(include)
# Aggiungi anche i file .h dalla cartella "salticidae/include/salticidae"
file(GLOB SALTICIDAE_HEADER_FILES "../salticidae/include/salticidae/*.h")
include_directories(salticidae/include)

# Unisci i due elenchi di file .h
set(ALL_HEADER_FILES ${HEADER_FILES} ${SALTICIDAE_HEADER_FILES})

add_executable(hotstuff-app hotstuff_app.cpp ${ALL_HEADER_FILES})
target_link_libraries(hotstuff-app hotstuff_static example)

add_executable(hotstuff-client hotstuff_client.cpp)
target_link_libraries(hotstuff-client hotstuff_static example)


add_executable(frost-app hotstuff_frost_app.cpp ${ALL_HEADER_FILES})
target_link_libraries(frost-app hotstuff_static example)
