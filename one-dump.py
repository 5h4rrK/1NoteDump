import re
import os
import sys


'''
It is a python script that scans for the EmbeddedGuidfileType(Same for all emebedded files) 
and followed by terminating part (same for all) that keeps track of file types.

'''

guidHeader = bytes.fromhex("E4525C7B8CD8A74DAEB15378D02996D3")

file = open(f"{sys.argv[1]}","rb").read()
try:
    assert file[:16] == guidHeader and file[32:48] == bytes.fromhex("00" * 16)
 
except:
    print("Error Occured In Parsing !!!")
    sys.exit(-1)

embedguidFileType = bytes.fromhex("E716E3BD65261145A4C48D4D0B7A9EAC")

getFileName = bytes.fromhex(
    "0014CE3400143F1C00209C1D001C221C001C9D1D001C141C0014151C0014841C00141B1C00141C1C0014")

endPayload = bytes.fromhex("3C00690066006E00640066003E00")

getFileName = bytes.fromhex(
    "0014CE3400143F1C00209C1D001C221C")

class Parser:
    start_indexes = None
    embedfile_len = None
    embedfile_null = None
    embedfile_reserved = None
    payload = None
    end_parts = None
    extension_indexes = None
    file_types = []
    embedlocalguid = []
    position = []
    file_names = []
    file_name_len = []
    file_name_start_index = []
    file_path = []
    

    def __init__(self,file) -> None:

        self.start_indexes = [i.start() for i in re.finditer(embedguidFileType,file)]
   
        self.embedfile_len = [int.from_bytes(file[i+16:i+16+8],"little") for i in self.start_indexes]

        self.end_parts = [i.start() for i in re.finditer(endPayload,file)]

        self.embedfile_null = [int.from_bytes(file[i+24:i+28],"big") for i in self.start_indexes]

        self.embedfile_reserved = [int.from_bytes(file[i+28:i+28+8],"big") for i in self.start_indexes]

        self.extension_indexes = [int.from_bytes(file[self.end_parts[i]+90:\
                                                      self.end_parts[i]+90+4], "little") for i in range(len(self.end_parts))]
        
        self.position = [i for i in range(len(file)-16)
                    if file[i:i+16] == getFileName]


        print("Embed Start Index = ",self.start_indexes)
        print("Embed File Len = ",self.embedfile_len)
        print("End Parts = ",self.end_parts)
        print("Extension Indexes = ",self.extension_indexes)
        self.getLocal_GUID(file)
        self.getFileExtension(file)
        self.findNames(file)
        self.extractPath(file)
        self.extract_payload(file)
        self.dumpReport()
        
        print("File Types", self.file_types)

    def getLocal_GUID(self,file):

        for _ in range(len(self.end_parts)):
            temp = file[self.end_parts[_]+14:self.end_parts[_]+76+14]
            __guid = ''
            for k in range(0,len(temp),2):
                __guid += chr(temp[k])
            self.embedlocalguid.append(__guid)
            print(__guid)


    def getFileExtension(self,file):

        for _ in range(len(self.extension_indexes)):
            __extension = ''
            temp = file[self.end_parts[_]+94:self.end_parts[_] + 94 + self.extension_indexes[_]*2]
            for k in range(0,len(temp),2):
                __extension += chr(temp[k])
            self.file_types.append(__extension)
        

    def dumpReport(self):

        temp_ = ''
        for _ in range(len(self.file_types)):
            temp_ += (self.embedlocalguid[_]  + '        ' + self.file_types[_] + '\n\n')
        open("Objects/Parsed-Report.txt","w").write(temp_)


    def extract_payload(self,file):

        if not os.path.exists('Objects'):
            print("Created Directory Objects")
            os.mkdir('Objects')
        else:
            os.system("rm -rf Objects/*")

        print("Dumping files in Objects")

        for i in range(len(self.start_indexes)):

            open(f"Objects/file{i}{self.file_types[i]}", "wb").write(\
                file[self.start_indexes[i]+36:\
                     self.start_indexes[i]+36+\
                        self.embedfile_len[i]])
            

    def findNames(self,file):

        __filename_temp_buff = []
        for _ in range(len(self.position)):

            __filename_temp_buff.append(file[self.position[_]:self.position[_] + 16*5])
        
        for i in range(len(__filename_temp_buff)):

            for j in range(len(__filename_temp_buff[i])-4):                   # Looking for ? Ex: ?...?
                if (__filename_temp_buff[i][j] == 63 and __filename_temp_buff[i][j+4] == 63):
                    self.file_name_start_index.append(self.position[i] + j + 5 + 4)
                    self.file_name_len.append(int.from_bytes(((file[self.position[i] + j + 5:self.position[i] + j + 8])), 'little'))

                
        for i in range(len(self.file_name_len)):

            z = ''
            buff = file[self.file_name_start_index[i]
                : self.file_name_start_index[i] + self.file_name_len[i]]
            for _ in range(0, len(buff), 2):
                z += chr(buff[_])
            self.file_names.append(z)
            print(z)
        
    def extractPath(self,file):
        return

Parser(file)
