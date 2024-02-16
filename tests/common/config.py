import tempfile
import os


def make_tmp(content):
    f = tempfile.NamedTemporaryFile(delete=False)
    print("make_tmp filename: " + f.name)
    f.write(bytes(content, "utf-8"))
    f.close()
    return f.name


def delete_tmp(filename):
    print("delete_tmp filename: " + filename)
    os.unlink(filename)
