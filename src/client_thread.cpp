#include "mariatds.h"
#include <sys/socket.h>
#include <unistd.h>
#include <codecvt>

using namespace std;

#define MSSQL_MAJOR     15
#define MSSQL_MINOR     0
#define MSSQL_BUILD     4033
#define MSSQL_SUBBUILD  0

static u16string utf8_to_utf16(const string_view& sv) {
    wstring_convert<codecvt_utf8_utf16<char16_t>, char16_t> convert;

    return convert.from_bytes(sv.data(), sv.data() + sv.length());
}

static string info_msg(bool error, int32_t msgno, uint8_t state, uint8_t severity,
                       const string_view& msg, const string_view& server, const string_view& proc,
                       uint32_t line_no) {
    string ret;
    auto msg_us = utf8_to_utf16(msg);
    auto server_us = utf8_to_utf16(server);
    auto proc_us = utf8_to_utf16(proc);
    size_t len = sizeof(tds_info_msg) +
                 sizeof(uint16_t) + (msg_us.length() * sizeof(char16_t)) +
                 sizeof(uint8_t) + (server_us.length() * sizeof(char16_t)) +
                 sizeof(uint8_t) + (proc_us.length() * sizeof(char16_t)) +
                 sizeof(uint32_t);

    ret.resize(sizeof(enum tds_token) + sizeof(uint16_t) + len);

    auto ptr = (uint8_t*)ret.data();

    *(enum tds_token*)ptr = error ? tds_token::TDS_ERROR : tds_token::INFO;
    ptr += sizeof(enum tds_token);

    *(uint16_t*)ptr = (uint16_t)len; ptr += sizeof(uint16_t);

    auto h = (tds_info_msg*)ptr;

    h->msgno = msgno;
    h->state = state;
    h->severity = severity;

    ptr += sizeof(tds_info_msg);

    *(uint16_t*)ptr = (uint16_t)msg_us.length(); ptr += sizeof(uint16_t);
    memcpy(ptr, msg_us.data(), msg_us.length() * sizeof(char16_t));
    ptr += msg_us.length() * sizeof(char16_t);

    *(uint8_t*)ptr = (uint8_t)server_us.length(); ptr += sizeof(uint8_t);
    memcpy(ptr, server_us.data(), server_us.length() * sizeof(char16_t));
    ptr += server_us.length() * sizeof(char16_t);

    *(uint8_t*)ptr = (uint8_t)proc_us.length(); ptr += sizeof(uint8_t);
    memcpy(ptr, proc_us.data(), proc_us.length() * sizeof(char16_t));
    ptr += proc_us.length() * sizeof(char16_t);

    *(uint32_t*)ptr = line_no;

    return ret;
}

string client_thread::recv(unsigned int len) {
    string s;
    int bytes, err = 0;

    if (len == 0)
        len = 4096;

    s.resize(len);

    do {
        bytes = (int)::recv(sock, s.data(), len, 0);

        if (bytes == -1)
            err = errno;
    } while (bytes == -1 && err == EWOULDBLOCK);

    if (bytes == 0 || (bytes == -1 && err == ECONNRESET)) {
        open = false;
        return "";
    } else if (bytes == -1)
        throw formatted_error(FMT_STRING("recv failed ({})"), err);

    return s.substr(0, bytes);
}

void client_thread::prelogin_msg(const string_view& packet) {
    string_view sv = packet;
    vector<login_opt> in_opts, out_opts;

    if (state != client_state::prelogin)
        throw runtime_error("Prelogin message already received.");

    while (true) {
        if (!sv.empty() && (enum tds_login_opt_type)sv[0] == tds_login_opt_type::terminator)
            break;

        if (sv.length() < sizeof(tds_login_opt))
            throw runtime_error("Malformed prelogin request.");

        auto opt = *(tds_login_opt*)sv.data();
        opt.offset = __builtin_bswap16(opt.offset);
        opt.length = __builtin_bswap16(opt.length);

        if (opt.length != 0) {
            if (opt.offset > packet.length() || opt.offset + opt.length > packet.length())
                throw runtime_error("Malformed prelogin request.");

            in_opts.emplace_back(opt.type, packet.substr(opt.offset, opt.length));
        } else
            in_opts.emplace_back(opt.type, "");

        sv = sv.substr(sizeof(tds_login_opt));
    }

    for (const auto& opt : in_opts) {
        switch (opt.type) {
            case tds_login_opt_type::version: {
                if (opt.payload.length() < sizeof(tds_login_opt_version))
                    throw formatted_error(FMT_STRING("Version option was {} bytes, expected {}."), opt.payload.length(), sizeof(tds_login_opt_version));

                tds_login_opt_version out_ver;

                out_ver.major = MSSQL_MAJOR;
                out_ver.minor = MSSQL_MINOR;
                out_ver.build = __builtin_bswap16(MSSQL_BUILD);
                out_ver.subbuild = __builtin_bswap16(MSSQL_SUBBUILD);

                out_opts.emplace_back(tds_login_opt_type::version, string_view((char*)&out_ver, sizeof(out_ver)));
                break;
            }

            case tds_login_opt_type::encryption: {
                if (opt.payload.length() < sizeof(enum tds_encryption_type))
                    throw formatted_error(FMT_STRING("Encryption option was {} bytes, expected {}."), opt.payload.length(), sizeof(enum tds_encryption_type));

                auto enc = (enum tds_encryption_type)opt.payload[0];

                if (enc != tds_encryption_type::ENCRYPT_OFF && enc != tds_encryption_type::ENCRYPT_NOT_SUP)
                    throw runtime_error("Encryption not supported.");

                out_opts.emplace_back(tds_login_opt_type::encryption, string_view("\x02", 1)); // ENCRYPT_NOT_SUP

                break;
            }

            case tds_login_opt_type::instopt:
                out_opts.emplace_back(tds_login_opt_type::instopt, string_view("\x00", 1));
                break;

            case tds_login_opt_type::threadid:
                out_opts.emplace_back(tds_login_opt_type::threadid, "");
                break;

            case tds_login_opt_type::mars:
                out_opts.emplace_back(tds_login_opt_type::mars, string_view("\x00", 1)); // MARS is off
                break;

            default:
                break;
        }
    }

    size_t len = sizeof(enum tds_login_opt_type);
    unsigned int num_opts = 0;

    for (const auto& opt : out_opts) {
        len += sizeof(tds_login_opt);
        len += opt.payload.length();
        num_opts++;
    }

    string ret;

    ret.resize(len);

    auto oh = (tds_login_opt*)ret.data();
    auto ptr = ret.data() + (num_opts * sizeof(tds_login_opt)) + sizeof(enum tds_login_opt_type);

    for (const auto& opt : out_opts) {
        oh->type = opt.type;
        oh->offset = __builtin_bswap16((uint16_t)(ptr - ret.data()));
        oh->length = __builtin_bswap16((uint16_t)opt.payload.length());

        if (!opt.payload.empty()) {
            memcpy(ptr, opt.payload.data(), opt.payload.length());
            ptr += opt.payload.length();
        }

        oh++;
    }

    oh->type = tds_login_opt_type::terminator;

    state = client_state::login;

    send_msg(tds_msg::tabular_result, ret);
}

static string utf16_to_utf8(const u16string_view& sv) {
    wstring_convert<codecvt_utf8_utf16<char16_t>, char16_t> convert;

    return convert.to_bytes(sv.data(), sv.data() + sv.length());
}

static string loginack_msg(uint8_t interface, uint32_t tds_version, const u16string_view& server_name) {
    string ret;

    ret.resize(13 + (server_name.length() * sizeof(char16_t)));

    auto ptr = (uint8_t*)ret.data();

    *(enum tds_token*)ptr = tds_token::LOGINACK; ptr += sizeof(enum tds_token);
    *(uint16_t*)ptr = (uint16_t)ret.length() - 3; ptr += sizeof(uint16_t);

    *ptr = interface; ptr++;
    *(uint32_t*)ptr = __builtin_bswap32(tds_version); ptr += sizeof(uint32_t);

    *ptr = (uint8_t)server_name.length(); ptr++;

    memcpy(ptr, server_name.data(), server_name.length() * sizeof(char16_t));
    ptr += server_name.length() * sizeof(char16_t);

    *ptr = MSSQL_MAJOR; ptr++;
    *ptr = MSSQL_MINOR; ptr++;
    *(uint16_t*)ptr = __builtin_bswap16(MSSQL_BUILD);

    return ret;
}

static string done_msg(uint16_t status, uint16_t curcmd, uint64_t rowcount) {
    string ret;

    ret.resize(1 + sizeof(tds_done_msg));

    auto ptr = (uint8_t*)ret.data();

    *(enum tds_token*)ptr = tds_token::DONE; ptr += sizeof(enum tds_token);

    auto& h = *(tds_done_msg*)ptr;

    h.status = status;
    h.curcmd = curcmd;
    h.rowcount = rowcount;

    return ret;
}

static string envchange_msg(enum tds_envchange_type type, const u16string_view& new_value,
                            const u16string_view& old_value) {
    string ret;

    ret.resize(6 + ((new_value.length() + old_value.length()) * sizeof(char16_t)));

    auto ptr = (uint8_t*)ret.data();

    *(enum tds_token*)ptr = tds_token::ENVCHANGE; ptr += sizeof(enum tds_token);

    *(uint16_t*)ptr = (uint16_t)(ret.length() - 3); ptr += sizeof(uint16_t);

    *(enum tds_envchange_type*)ptr = type; ptr += sizeof(enum tds_envchange_type);

    *ptr = (uint8_t)new_value.length(); ptr++;
    memcpy(ptr, new_value.data(), new_value.length() * sizeof(char16_t));
    ptr += new_value.length() * sizeof(char16_t);

    *ptr = (uint8_t)old_value.length(); ptr++;
    memcpy(ptr, old_value.data(), old_value.length() * sizeof(char16_t));

    return ret;
}

static string envchange_msg_collation(const tds_collation* new_value, const tds_collation* old_value) {
    string ret;

    ret.resize(6 + (new_value ? sizeof(tds_collation) : 0) + (old_value ? sizeof(tds_collation) : 0));

    auto ptr = (uint8_t*)ret.data();

    *(enum tds_token*)ptr = tds_token::ENVCHANGE; ptr += sizeof(enum tds_token);

    *(uint16_t*)ptr = (uint16_t)(ret.length() - 3); ptr += sizeof(uint16_t);

    *(enum tds_envchange_type*)ptr = tds_envchange_type::collation; ptr += sizeof(enum tds_envchange_type);

    if (new_value) {
        *ptr = sizeof(tds_collation);
        ptr++;

        memcpy(ptr, new_value, sizeof(tds_collation));
        ptr += sizeof(tds_collation);
    } else {
        *ptr = 0;
        ptr++;
    }

    if (old_value) {
        *ptr = sizeof(tds_collation);
        ptr++;

        memcpy(ptr, old_value, sizeof(tds_collation));
        ptr += sizeof(tds_collation);
    } else {
        *ptr = 0;
        ptr++;
    }

    return ret;
}

void client_thread::login_msg(const string_view& packet) {
    u16string_view username, database;
    string password;
#if 0
    u16string_view client_name, server_name, app_name, interface_library, database, attach_db;
    string new_password;
#endif

    if (state == client_state::prelogin)
        throw runtime_error("Prelogin message not yet received.");
    else if (state != client_state::login)
        throw runtime_error("Already logged in.");

    if (packet.length() < sizeof(tds_login_msg))
        throw formatted_error(FMT_STRING("Received {} bytes, expected at least {}."), packet.length(), sizeof(tds_login_msg));

    auto& msg = *(tds_login_msg*)packet.data();

    if (msg.length > packet.length())
        throw formatted_error(FMT_STRING("Message length {} was longer than packet length {}."), msg.length, packet.length());

    // FIXME - check tds_version
    // FIXME - check option_flags1, option_flags2, sql_type_flags, option_flags3
    // FIXME - store collation (and timezone?)

#if 0
    if (msg.client_name_length > 0) {
        if (msg.client_name_offset > msg.length || msg.client_name_offset + msg.client_name_length > msg.length)
            throw runtime_error("Malformed login message.");

        client_name = u16string_view((char16_t*)(packet.data() + msg.client_name_offset), msg.client_name_length);
    }
#endif

    if (msg.username_length > 0) {
        if (msg.username_offset > msg.length || msg.username_offset + msg.username_length > msg.length)
            throw runtime_error("Malformed login message.");

        username = u16string_view((char16_t*)(packet.data() + msg.username_offset), msg.username_length);
    }

    if (msg.password_length > 0) {
        if (msg.password_offset > msg.length || msg.password_offset + msg.password_length > msg.length)
            throw runtime_error("Malformed login message.");

        auto password_enc = u16string_view((char16_t*)(packet.data() + msg.password_offset), msg.password_length);
        u16string password_utf16;

        password_utf16.resize(msg.password_length);

        auto pw_src = (uint8_t*)password_enc.data();
        auto pw_dest = (uint8_t*)password_utf16.data();

        for (unsigned int i = 0; i < password_enc.length() * sizeof(char16_t); i++) {
            uint8_t c = *pw_src;

            c ^= 0xa5;
            c = (uint8_t)(((c & 0xf) << 4) | (c >> 4));

            *pw_dest = c;

            pw_src++;
            pw_dest++;
        }

        password = utf16_to_utf8(password_utf16);
    }

#if 0
    if (msg.app_name_length > 0) {
        if (msg.app_name_offset > msg.length || msg.app_name_offset + msg.app_name_length > msg.length)
            throw runtime_error("Malformed login message.");

        app_name = u16string_view((char16_t*)(packet.data() + msg.app_name_offset), msg.app_name_length);
    }

    if (msg.server_name_length > 0) {
        if (msg.server_name_offset > msg.length || msg.server_name_offset + msg.server_name_length > msg.length)
            throw runtime_error("Malformed login message.");

        server_name = u16string_view((char16_t*)(packet.data() + msg.server_name_offset), msg.server_name_length);
    }

    // FIXME - get extension features (esp. UTF-8)

    if (msg.interface_library_length > 0) {
        if (msg.interface_library_offset > msg.length || msg.interface_library_offset + msg.interface_library_length > msg.length)
            throw runtime_error("Malformed login message.");

        interface_library = u16string_view((char16_t*)(packet.data() + msg.interface_library_offset), msg.interface_library_length);
    }

    if (msg.locale_length > 0) {
        if (msg.locale_offset > msg.length || msg.locale_offset + msg.locale_length > msg.length)
            throw runtime_error("Malformed login message.");

        locale = u16string_view((char16_t*)(packet.data() + msg.locale_offset), msg.locale_length);
    }
#endif

    if (msg.database_length > 0) {
        if (msg.database_offset > msg.length || msg.database_offset + msg.database_length > msg.length)
            throw runtime_error("Malformed login message.");

        database = u16string_view((char16_t*)(packet.data() + msg.database_offset), msg.database_length);
    }

    // FIXME - SSPI

#if 0
    if (msg.attach_db_length > 0) {
        if (msg.attach_db_offset > msg.length || msg.attach_db_offset + msg.attach_db_length > msg.length)
            throw runtime_error("Malformed login message.");

        attach_db = u16string_view((char16_t*)(packet.data() + msg.attach_db_offset), msg.attach_db_length);
    }

    if (msg.new_password_length > 0) {
        if (msg.new_password_offset > msg.length || msg.new_password_offset + msg.new_password_length > msg.length)
            throw runtime_error("Malformed login message.");

        auto new_password_enc = u16string_view((char16_t*)(packet.data() + msg.new_password_offset), msg.new_password_length);
        u16string new_password_utf16;

        new_password_utf16.resize(msg.new_password_length);

        auto pw_src = (uint8_t*)new_password_enc.data();
        auto pw_dest = (uint8_t*)new_password_utf16.data();

        for (unsigned int i = 0; i < new_password_enc.length() * sizeof(char16_t); i++) {
            uint8_t c = *pw_src;

            c ^= 0xa5;
            c = (uint8_t)(((c & 0xf) << 4) | (c >> 4));

            *pw_dest = c;

            pw_src++;
            pw_dest++;
        }

        new_password = utf16_to_utf8(new_password_utf16);
    }
#endif

    mysql_init(&mysql);
    init_mysql = true;

    if (database.empty())
        database = u"test"; // FIXME

    if (!mysql_real_connect(&mysql, "luthien"/*FIXME*/, utf16_to_utf8(username).c_str(), password.c_str(),
                            database.empty() ? nullptr : utf16_to_utf8(database).c_str(), 0, nullptr, CLIENT_MULTI_STATEMENTS)) {
        const char* err = mysql_error(&mysql);

        if (!err)
            throw runtime_error("mysql_real_connect failed");

        throw runtime_error(err);
    }

    // FIXME - set SQL_MODE to MSSQL

    string ret;
    const char* cur_db;

    if (!mariadb_get_infov(&mysql, MARIADB_CONNECTION_SCHEMA, &cur_db) && cur_db) {
        ret += envchange_msg(tds_envchange_type::database, utf8_to_utf16(cur_db), u"master");

        ret += info_msg(false, 5701, 2, 0, "Changed database context to '"s + cur_db + "'."s, ""/*FIXME - server*/, "", 1);
    }

    memset(&def_collation, 0, sizeof(def_collation));
    def_collation.lcid = 1033; // FIXME
    def_collation.ignore_case = 1;
    def_collation.ignore_width = 1;
    def_collation.ignore_kana = 1;
    // FIXME - set utf8 flag if client supports it

    ret += envchange_msg_collation(&def_collation, nullptr);
    ret += envchange_msg(tds_envchange_type::language, u"us_english", u"");

    ret += info_msg(false, 5703, 1, 0, "Changed language setting to us_english.", ""/*FIXME - server*/, "", 1);

    ret += loginack_msg(1, 0x74000004, u"Microsoft SQL Server");

    ret += envchange_msg(tds_envchange_type::packet_size, u"4096", u"4096");

    // FIXME - feature ext ack

    ret += done_msg(0, 0, 0);

    send_msg(tds_msg::tabular_result, ret);

    state = client_state::connected;
}

static string field_metadata(const MYSQL_FIELD& f) {
    string ret;
    string_view name;
    size_t off = 0;

    ret.resize(sizeof(tds_colmetadata_col));

    auto h = (tds_colmetadata_col*)ret.data();

    h->user_type = 0;
    off = sizeof(tds_colmetadata_col);

    switch (f.type) {
        // FIXME - MYSQL_TYPE_DECIMAL

        case MYSQL_TYPE_TINY: // TINYINT
            h->flags = 0x80; // nullable
            h->type = sql_type::INTN;

            ret.resize(ret.length() + 1);
            ret[ret.length() - 1] = 1;
            off++;
        break;

        case MYSQL_TYPE_SHORT: // SMALLINT
            h->flags = 0x80; // nullable
            h->type = sql_type::INTN;

            ret.resize(ret.length() + 1);
            ret[ret.length() - 1] = 2;
            off++;
        break;

        case MYSQL_TYPE_INT24: // MEDIUMINT
        case MYSQL_TYPE_LONG: // INT
            h->flags = 0x80; // nullable
            h->type = sql_type::INTN;

            ret.resize(ret.length() + 1);
            ret[ret.length() - 1] = 4;
            off++;
        break;

        // FIXME - MYSQL_TYPE_FLOAT
        // FIXME - MYSQL_TYPE_DOUBLE
        // FIXME - MYSQL_TYPE_NULL
        // FIXME - MYSQL_TYPE_TIMESTAMP

        case MYSQL_TYPE_LONGLONG: // BIGINT
            h->flags = 0x80; // nullable
            h->type = sql_type::INTN;

            ret.resize(ret.length() + 1);
            ret[ret.length() - 1] = 8;
            off++;
        break;

        case MYSQL_TYPE_DATE: // DATE
            h->flags = 0x80; // nullable
            h->type = sql_type::DATE;
        break;

        // FIXME - MYSQL_TYPE_TIME
        // FIXME - MYSQL_TYPE_DATETIME
        // FIXME - MYSQL_TYPE_YEAR
        // FIXME - MYSQL_TYPE_NEWDATE
        // FIXME - MYSQL_TYPE_VARCHAR
        // FIXME - MYSQL_TYPE_BIT
        // FIXME - MYSQL_TYPE_JSON
        // FIXME - MYSQL_TYPE_NEWDECIMAL
        // FIXME - MYSQL_TYPE_ENUM
        // FIXME - MYSQL_TYPE_SET
        // FIXME - MYSQL_TYPE_TINY_BLOB
        // FIXME - MYSQL_TYPE_MEDIUM_BLOB
        // FIXME - MYSQL_TYPE_LONG_BLOB
        // FIXME - MYSQL_TYPE_BLOB

        case MYSQL_TYPE_VAR_STRING: { // VARCHAR
            // FIXME - NVARCHAR or NVARCHAR(MAX) if UTF-16 or UCS-2
            // FIXME - UTF-8 (when in UTF-8 mode)

            h->flags = 0x80; // nullable
            h->type = sql_type::VARCHAR;

            ret.resize(ret.length() + sizeof(uint16_t) + sizeof(tds_collation));

            *(uint16_t*)(ret.data() + off) = f.length > 8000 ? 0xffff : (uint16_t)f.length;
            off += sizeof(uint16_t);

            auto coll = (tds_collation*)(ret.data() + off);

            // FIXME - collation
            coll->lcid = 1033; // en-US
            coll->ignore_case = 1;
            coll->ignore_accent = 0;
            coll->ignore_width = 1;
            coll->ignore_kana = 1;
            coll->binary = 0;
            coll->binary2 = 0;
            coll->utf8 = 0;
            coll->reserved = 0;
            coll->version = 0;
            coll->sort_id = 0;

            off += sizeof(tds_collation);

            break;
        }

        // FIXME - MYSQL_TYPE_STRING
        // FIXME - MYSQL_TYPE_GEOMETRY

        default: {
            h->flags = 0x80; // nullable
            h->type = sql_type::INTN;

            ret.resize(ret.length() + 1);
            ret[ret.length() - 1] = 4;
            off++;
        }
    }

    // FIXME - append type length, collation, precision, scale

    if (f.name)
        name = string_view(f.name, f.name_length);

    auto name_utf16 = utf8_to_utf16(name);

    ret.resize(ret.length() + sizeof(uint8_t) + (name_utf16.length() * sizeof(char16_t)));

    *(uint8_t*)(ret.data() + off) = (uint8_t)name_utf16.length();
    off++;

    memcpy(ret.data() + off, name_utf16.data(), name_utf16.length() * sizeof(char16_t));

    return ret;
}

static string colmetadata_msg(MYSQL_RES* res) {
    string ret;
    auto field_count = mysql_num_fields(res);

    if (field_count > 65535)
        throw runtime_error("Too many columns.");

    ret.resize(3);

    auto ptr = (uint8_t*)ret.data();

    *(enum tds_token*)ptr = tds_token::COLMETADATA; ptr += sizeof(enum tds_token);
    *(uint16_t*)ptr = (uint16_t)field_count; ptr += sizeof(uint16_t);

    for (unsigned int i = 0; i < field_count; i++) {
        auto f = mysql_fetch_field(res);

        ret += field_metadata(*f);
    }

    return ret;
}

static string row_msg(const vector<MYSQL_BIND>& bind) {
    string ret;
    size_t off;
    unsigned int i;

    // FIXME - send NBC_ROW if more efficient
    // FIXME - UNSIGNED integers

    ret.resize(1);
    *(enum tds_token*)ret.data() = tds_token::ROW;

    off = 1;
    i = 0;

    for (const auto& b : bind) {
        switch (b.buffer_type) {
            case MYSQL_TYPE_TINY: // TINYINT
                if (*b.is_null) {
                    ret.resize(ret.length() + 1);
                    ret[off] = 0;
                    off++;
                } else {
                    ret.resize(ret.length() + 1 + sizeof(uint8_t));
                    ret[off] = 1;
                    off++;

                    *(uint8_t*)(&ret[off]) = *(uint8_t*)b.buffer;
                    off += sizeof(uint8_t);
                }
            break;

            case MYSQL_TYPE_SHORT: // SMALLINT
                if (*b.is_null) {
                    ret.resize(ret.length() + 1);
                    ret[off] = 0;
                    off++;
                } else {
                    ret.resize(ret.length() + 1 + sizeof(int16_t));
                    ret[off] = 2;
                    off++;

                    *(int16_t*)(&ret[off]) = *(int16_t*)b.buffer;
                    off += sizeof(int16_t);
                }
            break;

            case MYSQL_TYPE_INT24: // MEDIUMINT
            case MYSQL_TYPE_LONG: // INT
                if (*b.is_null) {
                    ret.resize(ret.length() + 1);
                    ret[off] = 0;
                    off++;
                } else {
                    ret.resize(ret.length() + 1 + sizeof(int32_t));
                    ret[off] = 4;
                    off++;

                    *(int32_t*)(&ret[off]) = *(int32_t*)b.buffer;
                    off += sizeof(int32_t);
                }
            break;

            case MYSQL_TYPE_LONGLONG: // BIGINT
                if (*b.is_null) {
                    ret.resize(ret.length() + 1);
                    ret[off] = 0;
                    off++;
                } else {
                    ret.resize(ret.length() + 1 + sizeof(int64_t));
                    ret[off] = 8;
                    off++;

                    *(int64_t*)(&ret[off]) = *(int64_t*)b.buffer;
                    off += sizeof(int64_t);
                }
            break;

            case MYSQL_TYPE_VAR_STRING: { // VARCHAR
                if (b.buffer_length > 8000) {
                    ret.resize(ret.length() + sizeof(uint64_t));

                    auto size = (uint64_t*)(ret.data() + off);
                    off += sizeof(uint64_t);

                    if (*b.is_null)
                        *size = 0xffffffffffffffff;
                    else if (*b.length == 0) {
                        *size = 0;

                        ret.resize(ret.length() + sizeof(uint32_t));

                        auto size2 = (uint32_t*)(ret.data() + off);
                        off += sizeof(uint32_t);

                        *size2 = 0;
                    } else {
                        *size = *b.length;

                        ret.resize(ret.length() + sizeof(uint32_t) + *b.length + sizeof(uint32_t));

                        auto size2 = (uint32_t*)(ret.data() + off);
                        off += sizeof(uint32_t);

                        *size2 = (uint16_t)*b.length;

                        memcpy(ret.data() + off, b.buffer, *b.length);
                        off += *b.length;

                        *(uint32_t*)(ret.data() + off) = 0;
                        off += sizeof(uint32_t);
                    }
                } else {
                    ret.resize(ret.length() + sizeof(uint16_t));

                    auto size = (uint16_t*)(ret.data() + off);
                    off += sizeof(uint16_t);

                    if (*b.is_null)
                        *size = 0xffff;
                    else if (*b.length == 0)
                        *size = 0;
                    else {
                        *size = (uint16_t)*b.length;

                        ret.resize(ret.length() + *b.length);
                        memcpy(ret.data() + off, b.buffer, *b.length);
                        off += *b.length;
                    }
                }

                break;
            }

            case MYSQL_TYPE_DATE:
                if (*b.is_null) {
                    ret.resize(ret.length() + sizeof(uint8_t));
                    *(uint8_t*)(ret.data() + off) = 0;
                    off++;
                } else {
                    int64_t n;
                    int m2, num;

                    ret.resize(ret.length() + sizeof(uint8_t) + 3);
                    *(uint8_t*)(ret.data() + off) = 3;
                    off++;

                    auto& tm = *(MYSQL_TIME*)b.buffer;

                    m2 = ((int)tm.month - 14) / 12;

                    n = (1461 * ((int)tm.year + 4800 + m2)) / 4;
                    n += (367 * ((int)tm.month - 2 - (12 * m2))) / 12;
                    n -= (3 * (((int)tm.year + 4900 + m2)/100)) / 4;
                    n += tm.day;
                    n -= 1753501;

                    num = static_cast<int>(n);

                    memcpy(ret.data() + off, &num, 3);

                    off += 3;
                }
            break;

            default:
                ret.resize(ret.length() + sizeof(uint8_t));
                *(uint8_t*)(ret.data() + off) = 0;
                off++;
        }

        i++;
    }

    return ret;
}

string client_thread::rows_msg(MYSQL_STMT* stmt, MYSQL_RES* res, uint64_t& row_count) {
    string ret;
    auto field_count = mysql_num_fields(res);
    vector<MYSQL_BIND> bind;
    vector<char> error, is_null;
    vector<unsigned long> length;
    vector<vector<byte>> bufs;

    bind.resize(field_count);
    error.resize(field_count);
    is_null.resize(field_count);
    length.resize(field_count);
    bufs.resize(field_count);

    memset(bind.data(), 0, sizeof(MYSQL_BIND) * field_count);

    mysql_field_seek(res, 0);

    for (unsigned int i = 0; i < field_count; i++) {
        auto f = mysql_fetch_field(res);
        auto b = &bind[i];

        switch (f->type) {
            case MYSQL_TYPE_TINY: // TINYINT
                b->buffer_type = f->type;

                bufs[i].resize(sizeof(uint8_t));

                b->buffer = bufs[i].data();
                b->buffer_length = bufs[i].size();
            break;

            case MYSQL_TYPE_SHORT: // SMALLINT
                b->buffer_type = f->type;

                bufs[i].resize(sizeof(int16_t));

                b->buffer = bufs[i].data();
                b->buffer_length = bufs[i].size();
            break;

            case MYSQL_TYPE_INT24: // MEDIUMINT
            case MYSQL_TYPE_LONG: // INT
                b->buffer_type = f->type;

                bufs[i].resize(sizeof(int32_t));

                b->buffer = bufs[i].data();
                b->buffer_length = bufs[i].size();
            break;

            case MYSQL_TYPE_LONGLONG: // BIGINT
                b->buffer_type = f->type;

                bufs[i].resize(sizeof(int64_t));

                b->buffer = bufs[i].data();
                b->buffer_length = bufs[i].size();
            break;

            case MYSQL_TYPE_VAR_STRING: // VARCHAR
                b->buffer_type = f->type;

                bufs[i].resize(f->length);

                b->buffer = bufs[i].data();
                b->buffer_length = bufs[i].size();
            break;

            case MYSQL_TYPE_DATE: // DATE
                b->buffer_type = f->type;

                bufs[i].resize(sizeof(MYSQL_TIME));

                b->buffer = bufs[i].data();
                b->buffer_length = bufs[i].size();
            break;

            default:
                b->buffer_type = MYSQL_TYPE_NULL;
        }

        b->is_null = &is_null[i];
        b->length = &length[i];
        b->error = &error[i];
    }

    if (mysql_stmt_bind_result(stmt, bind.data())){
        auto err = mysql_stmt_error(stmt);

        if (err && err[0])
            throw runtime_error(err);
        else
            throw runtime_error("mysql_stmt_bind_result failed");
    }

    do {
        // FIXME - check for attention message

        auto retval = mysql_stmt_fetch(stmt);

        // FIXME - show warning message if MYSQL_DATA_TRUNCATED received? (Only once?)

        if (retval == MYSQL_NO_DATA)
            break;
        else if (retval && retval != MYSQL_DATA_TRUNCATED && retval != MYSQL_NO_DATA) {
            auto err = mysql_stmt_error(stmt);

            if (err && err[0])
                throw runtime_error(err);
            else
                throw runtime_error("mysql_stmt_fetch failed");
        }

        ret += row_msg(bind);

        row_count++;
    } while (true);

    return ret;
}

void client_thread::batch_msg(const string_view& packet) {
    if (state != client_state::connected)
        throw runtime_error("Not logged in.");

    try {
        if (packet.length() < sizeof(uint32_t))
            throw formatted_error(FMT_STRING("Packet length was {}, expected at least 4."), packet.length());

        auto header_length = *(uint32_t*)packet.data();

        if (packet.length() < header_length)
            throw formatted_error(FMT_STRING("Packet length was {}, expected at least {}."), packet.length(), header_length);

        auto query_utf16 = u16string_view((char16_t*)(packet.data() + header_length),
                                          (packet.length() - header_length) / sizeof(char16_t));
        auto query = utf16_to_utf8(query_utf16);

        auto stmt = mysql_stmt_init(&mysql);

        if (!stmt) {
            auto err = mysql_error(&mysql);

            if (err && err[0])
                throw runtime_error(err);
            else
                throw runtime_error("mysql_real_query failed");
        }

        uint64_t row_count = 0;
        unsigned int field_count = 0;
        string ret;

        try {
            if (mysql_stmt_prepare(stmt, query.data(), query.length())) {
                auto err = mysql_stmt_error(stmt);

                if (err && err[0])
                    throw runtime_error(err);
                else
                    throw runtime_error("mysql_stmt_prepare failed");
            }

            if (mysql_stmt_param_count(stmt) != 0)
                throw runtime_error("Batch queries cannot contain parameters.");

            auto res = mysql_stmt_result_metadata(stmt);

            if (res) {
                try {
                    // FIXME - send multiple packets if too big
                    // FIXME - what happens if EXEC call and multiple rowsets returned?

                    ret += colmetadata_msg(res);

                    if (mysql_stmt_execute(stmt)) {
                        auto err = mysql_stmt_error(stmt);

                        if (err && err[0])
                            throw runtime_error(err);
                        else
                            throw runtime_error("mysql_stmt_execute failed");
                    }

                    ret += rows_msg(stmt, res, row_count);
                } catch (...) {
                    mysql_free_result(res);
                    throw;
                }

                mysql_free_result(res);
            }
        } catch (...) {
            mysql_stmt_close(stmt);
            throw;
        }

        mysql_stmt_close(stmt);

        ret += done_msg(field_count != 0 ? 0x10 : 0, 0xc1, row_count);

        send_msg(tds_msg::tabular_result, ret);
    } catch (const exception& e) {
        string ret;

        ret = info_msg(true, 0, 0, 14, e.what(), "", "", 0); // FIXME - server name
        ret += done_msg(0, 0xc1, 0);
        send_msg(tds_msg::tabular_result, ret);
    }
}

void client_thread::handle_packet(const string_view& packet) {
    auto& h = *(tds_header*)packet.data();

    switch (h.type) {
        case tds_msg::sql_batch:
            batch_msg(packet.substr(sizeof(tds_header), h.length - sizeof(tds_header)));
            break;

        case tds_msg::tds7_login:
            login_msg(packet.substr(sizeof(tds_header), h.length - sizeof(tds_header)));
            break;

        case tds_msg::prelogin:
            prelogin_msg(packet.substr(sizeof(tds_header), h.length - sizeof(tds_header)));
            break;

        default:
            throw formatted_error(FMT_STRING("Unhandled packet type {}."), h.type);
    }
}

void client_thread::send_msg(enum tds_msg type, const string_view& data) {
    string packet;

    packet.resize(sizeof(tds_header) + data.length());

    auto& h = *(tds_header*)packet.data();

    h.type = type;
    h.status = 1;
    h.length = __builtin_bswap16((uint16_t)(sizeof(tds_header) + data.length()));
    h.spid = spid;
    h.packet_id = 0;
    h.window = 0;

    memcpy(packet.data() + sizeof(tds_header), data.data(), data.length());

    send(sock, packet.data(), packet.length(), 0);
}

void client_thread::send_error(const string_view& msg) {
    send_msg(tds_msg::tabular_result, info_msg(true, 0, 0, 14, msg, "", "", 0)); // FIXME - server name
}

void client_thread::run() {
    try {
        thread_id = this_thread::get_id();

        while (open) {
            while (buf.length() < sizeof(tds_header)) {
                buf += recv((unsigned int)(sizeof(tds_header) - buf.length()));

                if (!open)
                    break;
            }

            auto& h = *(tds_header*)buf.data();
            uint16_t len = __builtin_bswap16(h.length);

            if (len < sizeof(tds_header))
                throw formatted_error(FMT_STRING("Packet length was {}, expected at least {}."), len, sizeof(tds_header));

            while (buf.length() < len) {
                buf += recv((unsigned int)(len - buf.length()));

                if (!open)
                    break;
            }

            // FIXME - large packets

            handle_packet(string_view(buf).substr(0, len));

            buf = buf.substr(len);
        }
    } catch (const exception& e) {
        try {
            if (open)
                send_error(e.what());
        } catch (...) {
        }
    }

    thread del_thread([&]() {
        unique_lock<shared_mutex> guard(client_threads_mutex);

        for (auto it = client_threads.begin(); it != client_threads.end(); it++) {
            if (it->thread_id == thread_id) {
                client_threads.erase(it);
                break;
            }
        }
    });

    del_thread.detach();
}

client_thread::~client_thread() {
    close(sock);
    t.join();

    if (init_mysql)
        mysql_close(&mysql);
}
