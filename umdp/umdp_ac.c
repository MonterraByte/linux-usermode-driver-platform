#include "umdp_ac.h"

#include <linux/err.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#include "umdp_common.h"

struct permission_entry {
    struct list_head list;
    char* path;

    u32* allowed_irq_lines;
    size_t allowed_irq_lines_count;

    struct mmap_region* allowed_mmap_regions;
    size_t allowed_mmap_regions_count;

    struct port_io_region* allowed_port_io_regions;
    size_t allowed_port_io_regions_count;
};
static LIST_HEAD(permission_list);
static DECLARE_RWSEM(permission_lock);
#define for_each_permission(p) list_for_each_entry(p, &permission_list, list)
#define for_each_permission_safe(p, next) list_for_each_entry_safe(p, next, &permission_list, list)

static struct permission_entry* get_permission_entry_by_exe_path(const char* exe_path) {
    struct permission_entry* entry;
    for_each_permission(entry) {
        if (strcmp(exe_path, entry->path) == 0) {
            return entry;
        }
    }
    return NULL;
}

static void remove_permission_entry(struct permission_entry* p) {
    list_del(&p->list);
    kfree(p->path);
    kfree(p->allowed_irq_lines);
    kfree(p->allowed_mmap_regions);
    kfree(p->allowed_port_io_regions);
    kfree(p);
}

bool umdp_ac_can_access_irq(const char* exe_path, u32 irq) {
    down_read(&permission_lock);

    struct permission_entry* entry = get_permission_entry_by_exe_path(exe_path);
    if (entry != NULL) {
        for (size_t i = 0; i < entry->allowed_irq_lines_count; i++) {
            if (entry->allowed_irq_lines[i] == irq) {
                up_read(&permission_lock);
                return true;
            }
        }
    }

    up_read(&permission_lock);
    return false;
}

#define UMDP_PROC_DIR_NAME "umdp"

static struct proc_dir_entry* umdp_proc_dir = NULL;
static struct proc_dir_entry* umdp_permtab_entry = NULL;

static int permtab_show(struct seq_file* s, void* data __attribute__((unused))) {
    seq_puts(s, "Executable path\tAllowed IRQ lines\tAllowed mmap regions\tAllowed I/O port regions\n");
    down_read(&permission_lock);

    size_t i;
    struct permission_entry* entry;
    for_each_permission(entry) {
        seq_puts(s, entry->path);
        seq_putc(s, '\t');

        if (entry->allowed_irq_lines_count > 0) {
            for (i = 0; i < entry->allowed_irq_lines_count; i++) {
                seq_printf(s, i == 0 ? "%u" : ",%u", entry->allowed_irq_lines[i]);
            }
        } else {
            seq_puts(s, "none");
        }
        seq_putc(s, '\t');

        if (entry->allowed_mmap_regions_count > 0) {
            for (i = 0; i < entry->allowed_mmap_regions_count; i++) {
                seq_printf(s, i == 0 ? "0x%lx-0x%lx" : ",0x%lx-0x%lx", entry->allowed_mmap_regions[i].start,
                    entry->allowed_mmap_regions[i].start + entry->allowed_mmap_regions[i].size);
            }
        } else {
            seq_puts(s, "none");
        }
        seq_putc(s, '\t');

        if (entry->allowed_port_io_regions_count > 0) {
            for (i = 0; i < entry->allowed_port_io_regions_count; i++) {
                seq_printf(s, i == 0 ? "0x%llx-0x%llx" : ",0x%llx-0x%llx", entry->allowed_port_io_regions[i].start,
                    entry->allowed_port_io_regions[i].start + entry->allowed_port_io_regions[i].size);
            }
        } else {
            seq_puts(s, "none");
        }
        seq_putc(s, '\n');
    }

    up_read(&permission_lock);
    return 0;
}

enum permtab_parse_state {
    PERMTAB_START,
    PERMTAB_READING_PATH,
    PERMTAB_FINISHED_PATH,
    PERMTAB_READING_IRQ,
    PERMTAB_FINISHED_IRQS,
    PERMTAB_READING_MMAP_START,
    PERMTAB_READING_MMAP_END,
    PERMTAB_FINISHED_MMAPS,
    PERMTAB_READING_IO_PORT_START,
    PERMTAB_READING_IO_PORT_END,
    PERMTAB_READING_END_OF_LINE,
    PERMTAB_SKIPPING_TO_NEXT_LINE,
};

static int build_and_add_permission_entry(struct list_head* list_head, char* path, u32* allowed_irq_lines,
    size_t allowed_irq_lines_count, struct mmap_region* allowed_mmap_regions, size_t allowed_mmap_regions_count,
    struct port_io_region* allowed_port_io_regions, size_t allowed_port_io_regions_count) {
    if (path == NULL || (allowed_irq_lines_count > 0 && allowed_irq_lines == NULL)
        || (allowed_mmap_regions_count > 0 && allowed_mmap_regions == NULL)
        || (allowed_port_io_regions_count > 0 && allowed_port_io_regions == NULL)) {
        // sanity check failed
        printk(KERN_ERR "umdp: bug?");
        return -EINVAL;
    }

    struct permission_entry* entry = kmalloc(sizeof(struct permission_entry), GFP_KERNEL);
    if (entry == NULL) {
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&entry->list);
    entry->path = path;
    entry->allowed_irq_lines = allowed_irq_lines;
    entry->allowed_irq_lines_count = allowed_irq_lines_count;
    entry->allowed_mmap_regions = allowed_mmap_regions;
    entry->allowed_mmap_regions_count = allowed_mmap_regions_count;
    entry->allowed_port_io_regions = allowed_port_io_regions;
    entry->allowed_port_io_regions_count = allowed_port_io_regions_count;

    list_add_tail(&entry->list, list_head);
    printk(KERN_DEBUG "umdp: added rule for path %s\n", entry->path);
    return 0;
}

static int finish_current_entry_and_reset_(enum permtab_parse_state* state, struct list_head* list_head, char** path,
    u32** allowed_irq_lines, size_t* allowed_irq_lines_count, struct mmap_region** allowed_mmap_regions,
    size_t* allowed_mmap_regions_count, struct port_io_region** allowed_port_io_regions,
    size_t* allowed_port_io_regions_count) {
    int ret = build_and_add_permission_entry(list_head, *path, *allowed_irq_lines, *allowed_irq_lines_count,
        *allowed_mmap_regions, *allowed_mmap_regions_count, *allowed_port_io_regions, *allowed_port_io_regions_count);
    if (ret != 0) {
        return ret;
    }

    *state = PERMTAB_START;
    *path = NULL;
    *allowed_irq_lines = NULL;
    *allowed_irq_lines_count = 0;
    *allowed_mmap_regions = NULL;
    *allowed_mmap_regions_count = 0;
    *allowed_port_io_regions = NULL;
    *allowed_port_io_regions_count = 0;

    return 0;
}

#define finish_current_entry_and_reset()                                                                               \
    finish_current_entry_and_reset_(&state, &new_permission_list, &path, &allowed_irq_lines, &allowed_irq_lines_count, \
        &allowed_mmap_regions, &allowed_mmap_regions_count, &allowed_port_io_regions, &allowed_port_io_regions_count)

static inline bool is_whitespace(char c) {
    return c == ' ' || c == '\t';
}

static inline bool is_hex_alpha(char c) {
    return (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

#define WHITESPACE ' ': case '\t'

static ssize_t permtab_write(struct file* file __attribute__((unused)), const char __user* permtab_text_user,
    size_t count, loff_t* offp __attribute__((unused))) {
    ssize_t ret = count;
    char* permtab_text = NULL;
    char* buffer = NULL;
    LIST_HEAD(new_permission_list);

    char* path = NULL;
    u32* allowed_irq_lines = NULL;
    size_t allowed_irq_lines_count = 0;
    struct mmap_region* allowed_mmap_regions = NULL;
    size_t allowed_mmap_regions_count = 0;
    struct port_io_region* allowed_port_io_regions = NULL;
    size_t allowed_port_io_regions_count = 0;

    permtab_text = kzalloc(count, GFP_KERNEL);
    if (permtab_text == NULL) {
        return -ENOMEM;
    }
    buffer = kmalloc(PATH_MAX, GFP_KERNEL);
    if (buffer == NULL) {
        ret = -ENOMEM;
        goto fail;
    }

    if (copy_from_user(permtab_text, permtab_text_user, count)) {
        ret = -1;
        goto fail;
    }

    size_t buffer_content_len = 0;
    bool reading_hex = false;
    int none_counter = 0;
    unsigned long mmap_start = 0;
    unsigned long mmap_end = 0;
    u64 io_port_start = 0;
    u64 io_port_end = 0;

    enum permtab_parse_state state = PERMTAB_START;
    for (size_t i = 0; i < count; i++) {
        char c = permtab_text[i];
        switch (state) {
            case PERMTAB_START:
                switch (c) {
                    case WHITESPACE:
                    case '\n':
                        continue;
                    case '#':
                        // comment line
                        state = PERMTAB_SKIPPING_TO_NEXT_LINE;
                        break;
                    case '/':
                        memset(buffer, 0, PATH_MAX);
                        buffer[0] = '/';
                        buffer_content_len = 1;
                        state = PERMTAB_READING_PATH;
                        break;
                    default:
                        printk(KERN_ERR "umdp: unexpected character '%c' in position %lu of permtab\n", c, i);
                        ret = -EINVAL;
                        goto fail;
                }
                break;
            case PERMTAB_READING_PATH:
                switch (c) {
                    case WHITESPACE:
                        path = kmalloc(buffer_content_len + 1, GFP_KERNEL);
                        if (path == NULL) {
                            ret = -ENOMEM;
                            goto fail;
                        }

                        memcpy(path, buffer, buffer_content_len);
                        path[buffer_content_len] = '\0';

                        state = PERMTAB_FINISHED_PATH;
                        break;
                    case '\n':
                        // todo: consider skipping this line instead
                        ret = -EINVAL;
                        goto fail;
                    default:
                        if (buffer_content_len >= PATH_MAX - 1) {
                            // todo: consider skipping this line instead
                            ret = -ENAMETOOLONG;
                            goto fail;
                        }
                        buffer[buffer_content_len] = c;
                        buffer_content_len++;
                        break;
                }
                break;
            case PERMTAB_FINISHED_PATH:
                if (none_counter > 0) {
                    if ((c == 'o' && none_counter == 1) || (c == 'n' && none_counter == 2)
                        || (c == 'e' && none_counter == 3)) {
                        none_counter++;
                        if (none_counter >= 4) {
                            none_counter = 0;
                            state = PERMTAB_FINISHED_IRQS;
                        }
                        continue;
                    } else {
                        // todo: consider skipping this line instead
                        ret = -EINVAL;
                        goto fail;
                    }
                }

                if (is_whitespace(c)) {
                    continue;
                } else if (isdigit(c)) {
                    buffer[0] = c;
                    buffer_content_len = 1;

                    state = PERMTAB_READING_IRQ;
                } else if (c == 'n') {
                    none_counter = 1;
                } else {
                    // todo: consider skipping this line instead
                    ret = -EINVAL;
                    goto fail;
                }
                break;
            case PERMTAB_READING_IRQ:
                if (isdigit(c) || ((c == 'x' || c == 'X') && buffer_content_len == 1 && buffer[0] == '0')
                    || (reading_hex && is_hex_alpha(c))) {
                    buffer[buffer_content_len] = c;
                    buffer_content_len++;

                    if (c == 'x' || c == 'X') {
                        reading_hex = true;
                    }
                } else if (is_whitespace(c) || c == ',') {
                    reading_hex = false;
                    if (buffer_content_len == 0) {
                        // skip trailing comma
                        if (is_whitespace(c)) {
                            state = PERMTAB_FINISHED_IRQS;
                        }
                        continue;
                    }

                    buffer[buffer_content_len] = '\0';
                    u32 irq;
                    int parse_result = kstrtou32(buffer, 0, &irq);
                    if (parse_result != 0) {
                        // todo: consider skipping this line instead
                        ret = parse_result;
                        goto fail;
                    }

                    allowed_irq_lines_count++;
                    u32* new_allowed_irq_lines =
                        krealloc_array(allowed_irq_lines, allowed_irq_lines_count, sizeof(u32), GFP_KERNEL);
                    if (new_allowed_irq_lines == NULL) {
                        ret = -ENOMEM;
                        goto fail;
                    }
                    allowed_irq_lines = new_allowed_irq_lines;
                    allowed_irq_lines[allowed_irq_lines_count - 1] = irq;

                    if (c == ',') {
                        buffer_content_len = 0;
                    } else {
                        state = PERMTAB_FINISHED_IRQS;
                    }
                } else {
                    // todo: consider skipping this line instead
                    ret = -EINVAL;
                    goto fail;
                }
                break;
            case PERMTAB_FINISHED_IRQS:
                if (none_counter > 0) {
                    if ((c == 'o' && none_counter == 1) || (c == 'n' && none_counter == 2)
                        || (c == 'e' && none_counter == 3)) {
                        none_counter++;
                        if (none_counter >= 4) {
                            none_counter = 0;
                            state = PERMTAB_FINISHED_MMAPS;
                        }
                        continue;
                    } else {
                        // todo: consider skipping this line instead
                        ret = -EINVAL;
                        goto fail;
                    }
                }

                if (is_whitespace(c)) {
                    continue;
                } else if (isdigit(c)) {
                    buffer[0] = c;
                    buffer_content_len = 1;

                    state = PERMTAB_READING_MMAP_START;
                } else if (c == 'n') {
                    none_counter = 1;
                } else {
                    // todo: consider skipping this line instead
                    ret = -EINVAL;
                    goto fail;
                }
                break;
            case PERMTAB_READING_MMAP_START:
                if (isdigit(c) || ((c == 'x' || c == 'X') && buffer_content_len == 1 && buffer[0] == '0')
                    || (reading_hex && is_hex_alpha(c))) {
                    buffer[buffer_content_len] = c;
                    buffer_content_len++;

                    if (c == 'x' || c == 'X') {
                        reading_hex = true;
                    }
                } else if (c == '-') {
                    reading_hex = false;
                    buffer[buffer_content_len] = '\0';
                    int parse_result = kstrtoul(buffer, 0, &mmap_start);
                    if (parse_result != 0) {
                        // todo: consider skipping this line instead
                        ret = parse_result;
                        goto fail;
                    }

                    buffer_content_len = 0;
                    state = PERMTAB_READING_MMAP_END;
                } else if (buffer_content_len == 0 && c == ',') {
                    // skip empty value comma
                    break;
                } else if (buffer_content_len == 0 && is_whitespace(c)) {
                    // skip trailing comma
                    state = PERMTAB_FINISHED_MMAPS;
                } else {
                    // todo: consider skipping this line instead
                    ret = -EINVAL;
                    goto fail;
                }
                break;
            case PERMTAB_READING_MMAP_END:
                if (isdigit(c) || ((c == 'x' || c == 'X') && buffer_content_len == 1 && buffer[0] == '0')
                    || (reading_hex && is_hex_alpha(c))) {
                    buffer[buffer_content_len] = c;
                    buffer_content_len++;

                    if (c == 'x' || c == 'X') {
                        reading_hex = true;
                    }
                } else if (is_whitespace(c) || c == ',') {
                    reading_hex = false;
                    buffer[buffer_content_len] = '\0';
                    int parse_result = kstrtoul(buffer, 0, &mmap_end);
                    if (parse_result != 0) {
                        // todo: consider skipping this line instead
                        ret = parse_result;
                        goto fail;
                    }

                    if (mmap_end <= mmap_start) {
                        // todo: consider skipping this line instead
                        ret = -EINVAL;
                        goto fail;
                    }

                    allowed_mmap_regions_count++;
                    struct mmap_region* new_allowed_mmap_regions = krealloc_array(
                        allowed_mmap_regions, allowed_mmap_regions_count, sizeof(struct mmap_region), GFP_KERNEL);
                    if (new_allowed_mmap_regions == NULL) {
                        ret = -ENOMEM;
                        goto fail;
                    }
                    allowed_mmap_regions = new_allowed_mmap_regions;
                    allowed_mmap_regions[allowed_mmap_regions_count - 1].start = mmap_start;
                    allowed_mmap_regions[allowed_mmap_regions_count - 1].size = mmap_end - mmap_start;

                    if (c == ',') {
                        buffer_content_len = 0;
                        state = PERMTAB_READING_MMAP_START;
                    } else {
                        state = PERMTAB_FINISHED_MMAPS;
                    }
                } else {
                    // todo: consider skipping this line instead
                    ret = -EINVAL;
                    goto fail;
                }
                break;
            case PERMTAB_FINISHED_MMAPS:
                if (none_counter > 0) {
                    if ((c == 'o' && none_counter == 1) || (c == 'n' && none_counter == 2)
                        || (c == 'e' && none_counter == 3)) {
                        none_counter++;
                        if (none_counter >= 4) {
                            none_counter = 0;
                            state = PERMTAB_READING_END_OF_LINE;
                        }
                        continue;
                    } else {
                        // todo: consider skipping this line instead
                        ret = -EINVAL;
                        goto fail;
                    }
                }

                if (is_whitespace(c)) {
                    continue;
                } else if (isdigit(c)) {
                    buffer[0] = c;
                    buffer_content_len = 1;

                    state = PERMTAB_READING_IO_PORT_START;
                } else if (c == 'n') {
                    none_counter = 1;
                } else {
                    // todo: consider skipping this line instead
                    ret = -EINVAL;
                    goto fail;
                }
                break;
            case PERMTAB_READING_IO_PORT_START:
                if (isdigit(c) || ((c == 'x' || c == 'X') && buffer_content_len == 1 && buffer[0] == '0')
                    || (reading_hex && is_hex_alpha(c))) {
                    buffer[buffer_content_len] = c;
                    buffer_content_len++;

                    if (c == 'x' || c == 'X') {
                        reading_hex = true;
                    }
                } else if (c == '-') {
                    reading_hex = false;
                    buffer[buffer_content_len] = '\0';
                    int parse_result = kstrtou64(buffer, 0, &io_port_start);
                    if (parse_result != 0) {
                        // todo: consider skipping this line instead
                        ret = parse_result;
                        goto fail;
                    }

                    buffer_content_len = 0;
                    state = PERMTAB_READING_IO_PORT_END;
                } else if (buffer_content_len == 0 && c == ',') {
                    // skip empty value comma
                    break;
                } else if (buffer_content_len == 0 && (is_whitespace(c) || c == '\n')) {
                    // skip trailing comma
                    if (c == '\n') {
                        finish_current_entry_and_reset();
                    } else {
                        state = PERMTAB_READING_END_OF_LINE;
                    }
                } else {
                    // todo: consider skipping this line instead
                    ret = -EINVAL;
                    goto fail;
                }
                break;
            case PERMTAB_READING_IO_PORT_END:
                if (isdigit(c) || ((c == 'x' || c == 'X') && buffer_content_len == 1 && buffer[0] == '0')
                    || (reading_hex && is_hex_alpha(c))) {
                    buffer[buffer_content_len] = c;
                    buffer_content_len++;

                    if (c == 'x' || c == 'X') {
                        reading_hex = true;
                    }
                } else if (is_whitespace(c) || c == ',' || c == '\n') {
                    reading_hex = false;
                    buffer[buffer_content_len] = '\0';
                    int parse_result = kstrtou64(buffer, 0, &io_port_end);
                    if (parse_result != 0) {
                        // todo: consider skipping this line instead
                        ret = parse_result;
                        goto fail;
                    }

                    if (io_port_end <= io_port_start) {
                        // todo: consider skipping this line instead
                        ret = -EINVAL;
                        goto fail;
                    }

                    allowed_port_io_regions_count++;
                    struct port_io_region* new_allowed_port_io_regions = krealloc_array(allowed_port_io_regions,
                        allowed_port_io_regions_count, sizeof(struct port_io_region), GFP_KERNEL);
                    if (new_allowed_port_io_regions == NULL) {
                        ret = -ENOMEM;
                        goto fail;
                    }
                    allowed_port_io_regions = new_allowed_port_io_regions;
                    allowed_port_io_regions[allowed_port_io_regions_count - 1].start = io_port_start;
                    allowed_port_io_regions[allowed_port_io_regions_count - 1].size = io_port_end - io_port_start;

                    if (c == ',') {
                        buffer_content_len = 0;
                        state = PERMTAB_READING_IO_PORT_START;
                    } else if (c == '\n') {
                        finish_current_entry_and_reset();
                    } else {
                        state = PERMTAB_READING_END_OF_LINE;
                    }
                } else {
                    // todo: consider skipping this line instead
                    ret = -EINVAL;
                    goto fail;
                }
                break;
            case PERMTAB_READING_END_OF_LINE:
                if (c == '\n') {
                    finish_current_entry_and_reset();
                } else if (is_whitespace(c)) {
                    continue;
                } else {
                    // todo: consider skipping this line instead
                    ret = -EINVAL;
                    goto fail;
                }
            case PERMTAB_SKIPPING_TO_NEXT_LINE:
                if (c == '\n') {
                    state = PERMTAB_START;
                }
                break;
        }
    }

    switch (state) {
        case PERMTAB_READING_END_OF_LINE:
            finish_current_entry_and_reset();
            break;
        case PERMTAB_START:
        case PERMTAB_SKIPPING_TO_NEXT_LINE:
            break;
        default:
            // unfinished line
            // todo: consider skipping this line instead
            ret = -EINVAL;
            goto fail;
    }


    down_write(&permission_lock);

    struct permission_entry* entry;
    struct permission_entry* next;
    for_each_permission_safe(entry, next) {
        printk(KERN_DEBUG "umdp: removing old rule for %s\n", entry->path);
        remove_permission_entry(entry);
    }

    list_bulk_move_tail(&permission_list, new_permission_list.next, new_permission_list.prev);

    up_write(&permission_lock);

fail:
    list_for_each_entry_safe(entry, next, &new_permission_list, list) {
        remove_permission_entry(entry);
    }
    kfree(allowed_port_io_regions);
    kfree(allowed_mmap_regions);
    kfree(allowed_irq_lines);
    kfree(path);
    kfree(buffer);
    kfree(permtab_text);
    printk(KERN_DEBUG "umdp: permtab_write exited with code %ld\n", ret);
    return ret;
}

static int permtab_open(struct inode* inode, struct file* file) {
    return single_open(file, permtab_show, NULL);
}

static const struct proc_ops umdp_permtab_ops = {
    .proc_open = permtab_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_write = permtab_write,
    .proc_release = single_release,
};

int umdp_ac_init(void) {
    umdp_proc_dir = proc_mkdir(UMDP_PROC_DIR_NAME, NULL);
    if (IS_ERR_OR_NULL(umdp_proc_dir)) {
        printk(KERN_ERR "umdp: Failed to create directory in procfs\n");
        return -1;
    }

    umdp_permtab_entry = proc_create("permtab", S_IRUSR | S_IWUSR, umdp_proc_dir, &umdp_permtab_ops);
    if (IS_ERR_OR_NULL(umdp_permtab_entry)) {
        printk(KERN_ERR "umdp: Failed to permtab file in procfs\n");
        return -1;
    }

    return 0;
}

void umdp_ac_exit(void) {
    remove_proc_entry("permtab", umdp_proc_dir);
    remove_proc_entry(UMDP_PROC_DIR_NAME, NULL);

    down_write(&permission_lock);

    struct permission_entry* entry;
    struct permission_entry* next;
    for_each_permission_safe(entry, next) {
        remove_permission_entry(entry);
    }

    up_write(&permission_lock);
}
