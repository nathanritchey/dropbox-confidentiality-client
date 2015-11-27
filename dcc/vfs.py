from uuid import uuid4
from os.path import basename, normpath, join
from os import getcwd

def chunks(seq, n):
    for i in xrange(0, len(seq), n):
        yield seq[i:i + n]

class VFS(object):

    def __init__(self):
        self.files = dict()
        self.tree = dict()

    def __len__(self):
        return len(self.files)

    def add_file(self, full_path):
        full_path = normpath(full_path)
        if full_path in self.files:
            return file_info[2]
        file_info = [basename(full_path), full_path, '%s' % uuid4()]
        self.files[file_info[1]] = file_info
        vfs_pointer = self.tree
        for component in file_info[1].split('/')[1:-1]:
            if not vfs_pointer.has_key(component):
                vfs_pointer[component] = dict()
            vfs_pointer = vfs_pointer[component]
        vfs_pointer[file_info[0]] = file_info
        return file_info[2]

    def get_file_uuid(self, path):
        path = normpath(join(getcwd(), path))
        if self.files.has_key(path):
            return (True, self.files[path][2])
        return (False, None)

    def list_files(self, path):
        path = normpath(join(getcwd(), path)).split('/')[1:]
        vfs_pointer = self.tree
        if path[0] != '':
            for component in path:
                if not vfs_pointer.has_key(component):
                    return None
                vfs_pointer = vfs_pointer[component]
        if type(vfs_pointer) is list:
            return [(True, vfs_pointer[0])]
        else:
            items = [(False, '.'), (False, '..')] if path[0] != '' else []
            for item in vfs_pointer.iterkeys():
                items.append((type(vfs_pointer[item]) is list, item))
            return items

    def print_list_files(self, path):
        files = self.list_files(path)
        if files is None:
            print('Error: Path `%s` does not exist or is a file.' % path)
        else:
            for row in chunks(files, 4):
                print('    '.join(map(lambda (is_folder, name): name, row)))

    def print_tree(self, component=None, indent=1):
        spacer = ''.join([' ' for _ in xrange(0, indent)])
        if component is None:
            component = self.tree
            print('/')
        for sub_component in component.iterkeys():
            if type(component[sub_component]) is list:
                print('%s%s (%s)' % (spacer, component[sub_component][0], component[sub_component][2]))
            else:
                print('%s%s/' % (spacer, sub_component))
                self.print_tree(component=component[sub_component], indent=indent+2)

if __name__ == '__main__':

    vfs_file = VFS()

    vfs_file.add_file(join(getcwd(), 'example/message.txt'))
    vfs_file.add_file(join(getcwd(), 'test.exe'))
    vfs_file.add_file('/opt/run.sh')
    
    vfs_file.print_tree()
    
    print(vfs_file.tree)

    while True:
        input = raw_input('> ').strip()
        if len(input) == 1 and input[0] == 'q':
            break
        vfs_file.print_list_files(input)