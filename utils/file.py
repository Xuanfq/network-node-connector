import os
import glob


def get_files(path: str, base_relative_path: str = None):
    """Get the all files and dirs in path

    path(str): absolute path or relative path
    base_relative_path(str): base/prefix path for caculate relative path value

    return((bool, list)): flag, list is a tuple list, tuple is (filename, relativepath, type), type is 'F' or 'D'
    """
    if len(path) == 0:
        return False, f"Invalid Parameters"
    if not path.startswith(".") and not path.startswith("/"):
        path = "." + os.path.sep + path
    if os.path.isdir(path):
        basepath = os.path.dirname(path)
        items = os.listdir(path)
    elif os.path.isfile(path):
        basepath = os.path.dirname(path)
        relativepath = path.replace(basepath, "", 1)
        while relativepath.startswith("/"):
            relativepath = relativepath.replace("/", "", 1)
        return True, [(path, relativepath, "F")]
    else:
        items = glob.glob(path)
        if len(items) == 0:
            # non file or dir
            return False, f"Invalid Parameters"
        else:
            basepath = os.path.dirname(items[0])
    if len(basepath) != 0:
        basepath += os.path.sep
    if base_relative_path is not None:
        basepath = base_relative_path
    files = []  # (filename, relativepath, type)
    for item in items:
        filepath = os.path.join(path, item)
        relativepath = filepath.replace(basepath, "", 1)
        while relativepath.startswith("/"):
            relativepath = relativepath.replace("/", "", 1)
        if os.path.isfile(filepath):
            files.append((filepath, relativepath, "F"))
        else:
            files.append((filepath, relativepath, "D"))
            flag, sub_files = get_files(filepath, basepath)
            if flag:
                files.extend(sub_files)
    return True, files
