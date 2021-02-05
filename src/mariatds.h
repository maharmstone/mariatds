#include <string>
#include <stdexcept>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <list>
#include <fmt/format.h>
#include <mariadb/mysql.h>

class sockets_error : public std::exception {
public:
    sockets_error(const std::string_view& func) : err(errno), msg(std::string(func) + " failed (error " + std::to_string(err) + ")") {
    }

    virtual const char* what() const noexcept {
        return msg.c_str();
    }

private:
    int err;
    std::string msg;
};

class formatted_error : public std::exception {
public:
	template<typename T, typename... Args>
	formatted_error(const T& s, Args&&... args) {
		msg = fmt::format(s, std::forward<Args>(args)...);
	}

	const char* what() const noexcept {
		return msg.c_str();
	}

private:
	std::string msg;
};

enum class tds_msg : uint8_t {
    sql_batch = 1,
    pretds7_login,
    rpc,
    tabular_result,
    attention_signal = 6,
    bulk_load_data,
    federated_auth_token,
    trans_man_req = 14,
    tds7_login = 16,
    sspi,
    prelogin
};

#pragma pack(push,1)

struct tds_header {
    enum tds_msg type;
    uint8_t status;
    uint16_t length;
    uint16_t spid;
    uint8_t packet_id;
    uint8_t window;
};

static_assert(sizeof(tds_header) == 8, "tds_header has wrong size");

struct tds_info_msg {
    int32_t msgno;
    uint8_t state;
    uint8_t severity;
};

static_assert(sizeof(tds_info_msg) == 6, "tds_info_msg has wrong size");

enum class tds_token : uint8_t {
    OFFSET = 0x78,
    RETURNSTATUS = 0x79,
    COLMETADATA = 0x81,
    ALTMETADATA = 0x88,
    DATACLASSIFICATION = 0xa3,
    TABNAME = 0xa4,
    COLINFO = 0xa5,
    ORDER = 0xa9,
    TDS_ERROR = 0xaa,
    INFO = 0xab,
    RETURNVALUE = 0xac,
    LOGINACK = 0xad,
    FEATUREEXTACK = 0xae,
    ROW = 0xd1,
    NBCROW = 0xd2,
    ALTROW = 0xd3,
    ENVCHANGE = 0xe3,
    SESSIONSTATE = 0xe4,
    SSPI = 0xed,
    FEDAUTHINFO = 0xee,
    DONE = 0xfd,
    DONEPROC = 0xfe,
    DONEINPROC = 0xff
};

enum class tds_login_opt_type : uint8_t {
    version = 0,
    encryption,
    instopt,
    threadid,
    mars,
    traceid,
    fedauthrequired,
    nonceopt,
    terminator = 0xff
};

struct login_opt {
    login_opt(enum tds_login_opt_type type, const std::string_view& payload) : type(type), payload(payload) { }

    enum tds_login_opt_type type;
    std::string payload;
};

struct tds_login_opt_version {
    uint8_t major;
    uint8_t minor;
    uint16_t build;
    uint16_t subbuild;
};

static_assert(sizeof(tds_login_opt_version) == 6, "login_opt_version has wrong size");

struct tds_login_opt {
    enum tds_login_opt_type type;
    uint16_t offset;
    uint16_t length;
};

static_assert(sizeof(tds_login_opt) == 5, "tds_login_opt has wrong size");

enum class tds_encryption_type : uint8_t {
    ENCRYPT_OFF,
    ENCRYPT_ON,
    ENCRYPT_NOT_SUP,
    ENCRYPT_REQ
};

struct tds_login_msg {
    uint32_t length;
    uint32_t tds_version;
    uint32_t packet_size;
    uint32_t client_version;
    uint32_t client_pid;
    uint32_t connexion_id;
    uint8_t option_flags1;
    uint8_t option_flags2;
    uint8_t sql_type_flags;
    uint8_t option_flags3;
    int32_t timezone;
    uint32_t collation;
    uint16_t client_name_offset;
    uint16_t client_name_length;
    uint16_t username_offset;
    uint16_t username_length;
    uint16_t password_offset;
    uint16_t password_length;
    uint16_t app_name_offset;
    uint16_t app_name_length;
    uint16_t server_name_offset;
    uint16_t server_name_length;
    uint16_t extension_offset;
    uint16_t extension_length;
    uint16_t interface_library_offset;
    uint16_t interface_library_length;
    uint16_t locale_offset;
    uint16_t locale_length;
    uint16_t database_offset;
    uint16_t database_length;
    uint8_t mac_address[6];
    uint16_t sspi_offset;
    uint16_t sspi_length;
    uint16_t attach_db_offset;
    uint16_t attach_db_length;
    uint16_t new_password_offset;
    uint16_t new_password_length;
    uint32_t sspi_long;
};

static_assert(sizeof(tds_login_msg) == 94, "tds_login_msg has wrong size");

struct tds_done_msg {
    uint16_t status;
    uint16_t curcmd;
    uint64_t rowcount;
};

static_assert(sizeof(tds_done_msg) == 12, "tds_done_msg has wrong size");

enum class tds_envchange_type : uint8_t {
    database = 1,
    language,
    charset,
    packet_size,
    unicode_data_sort_local_id,
    unicode_data_sort_comparison_flags,
    collation,
    begin_trans,
    commit_trans,
    rollback_trans,
    enlist_dist_trans,
    defect_trans,
    log_shipping,
    promote_trans = 15,
    trans_man_address,
    trans_ended,
    reset_completion_acknowledgement,
    user_instance_started,
    routing
};

struct tds_collation {
    uint32_t lcid : 20;
    uint32_t ignore_case : 1;
    uint32_t ignore_accent : 1;
    uint32_t ignore_width : 1;
    uint32_t ignore_kana : 1;
    uint32_t binary : 1;
    uint32_t binary2 : 1;
    uint32_t utf8 : 1;
    uint32_t reserved : 1;
    uint32_t version : 4;
    uint8_t sort_id;
};

static_assert(sizeof(tds_collation) == 5, "tds_collation has wrong size");

enum class sql_type : uint8_t {
    SQL_NULL = 0x1F,
    IMAGE = 0x22,
    TEXT = 0x23,
    UNIQUEIDENTIFIER = 0x24,
    INTN = 0x26,
    DATE = 0x28,
    TIME = 0x29,
    DATETIME2 = 0x2A,
    DATETIMEOFFSET = 0x2B,
    TINYINT = 0x30,
    BIT = 0x32,
    SMALLINT = 0x34,
    INT = 0x38,
    DATETIM4 = 0x3A,
    REAL = 0x3B,
    MONEY = 0x3C,
    DATETIME = 0x3D,
    FLOAT = 0x3E,
    SQL_VARIANT = 0x62,
    NTEXT = 0x63,
    BITN = 0x68,
    DECIMAL = 0x6A,
    NUMERIC = 0x6C,
    FLTN = 0x6D,
    MONEYN = 0x6E,
    DATETIMN = 0x6F,
    SMALLMONEY = 0x7A,
    BIGINT = 0x7F,
    VARBINARY = 0xA5,
    VARCHAR = 0xA7,
    BINARY = 0xAD,
    CHAR = 0xAF,
    NVARCHAR = 0xE7,
    NCHAR = 0xEF,
    UDT = 0xF0,
    XML = 0xF1,
};

struct tds_colmetadata_col {
    uint32_t user_type;
    uint16_t flags;
    sql_type type;
};

static_assert(sizeof(tds_colmetadata_col) == 7, "tds_colmetadata_col has wrong size");

#pragma pack(pop)

enum class client_state {
    prelogin,
    login,
    connected
};

class client_thread {
public:
    client_thread(unsigned int sock) : sock(sock), t([&]() {
        run();
    }) { }
    ~client_thread();

    std::thread::id thread_id;
    enum client_state state = client_state::prelogin;

private:
    void run();
    std::string recv(unsigned int len);
    void handle_packet(const std::string_view& packet);
    void send_error(const std::string_view& msg);
    void send_msg(enum tds_msg type, const std::string_view& data);
    void prelogin_msg(const std::string_view& packet);
    void login_msg(const std::string_view& packet);
    void batch_msg(const std::string_view& packet);

    unsigned int sock;
    std::thread t;
    std::string buf;
    bool open = true;
    uint16_t spid = 0;
    MYSQL mysql;
    bool init_mysql = false;
    tds_collation def_collation;
};

// mariatds.cpp
extern std::list<client_thread> client_threads;
extern std::shared_mutex client_threads_mutex;
