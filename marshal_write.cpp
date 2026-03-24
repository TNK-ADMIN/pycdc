#include "marshal_write.h"
#include "pyc_code.h"
#include "pyc_numeric.h"
#include "pyc_sequence.h"
#include "pyc_string.h"
#include "data.h"
#include "plusaes.hpp"
#include <cstring>
#include <cstdio>

/* ---- little-endian write helpers ---- */

static void put16(std::ostream& out, unsigned int v)
{
    out.put((char)(v & 0xFF));
    out.put((char)((v >> 8) & 0xFF));
}

static void put32(std::ostream& out, unsigned int v)
{
    out.put((char)(v & 0xFF));
    out.put((char)((v >> 8) & 0xFF));
    out.put((char)((v >> 16) & 0xFF));
    out.put((char)((v >> 24) & 0xFF));
}

static void put64(std::ostream& out, double v)
{
    // reinterpret as 8 raw bytes
    unsigned char buf[8];
    memcpy(buf, &v, 8);
    out.write(reinterpret_cast<const char*>(buf), 8);
}

/* ---- forward declaration ---- */
static void DumpCode(std::ostream& out, PycRef<PycCode> code, PycModule* mod);

/* ---- string helpers ---- */

/**
 * Write a PycString as raw bytes — no mix_str decryption.
 * Used for binary fields: co_code, lntable, exceptiontable, localkinds,
 * and identity strings: names, filename, co_name, co_qualname.
 */
static void DumpRawString(std::ostream& out, PycRef<PycString> str)
{
    int t = str->type();
    const std::string& value = str->strValue();
    out.put((char)t);
    if (t == PycObject::TYPE_SHORT_ASCII || t == PycObject::TYPE_SHORT_ASCII_INTERNED) {
        out.put((char)(value.size() & 0xFF));
    } else {
        put32(out, (unsigned int)value.size());
    }
    out.write(value.data(), (std::streamsize)value.size());
}

/**
 * Write a PycString, decrypting Pyarmor mix_str if present.
 * Used for string constants in co_consts.
 *
 * Mix_str detection (mirrors PycString::dasPrintAndDecrypt):
 *   - type is TYPE_STRING or TYPE_UNICODE
 *   - first byte has bit 7 set
 *   - low 7 bits of first byte are in [1..4]
 */
static void DumpMixStr(std::ostream& out, PycRef<PycString> str, PycModule* mod)
{
    const std::string& raw = str->strValue();
    int t = str->type();

    bool is_mixstr = (t == PycObject::TYPE_STRING || t == PycObject::TYPE_UNICODE)
                  && !raw.empty()
                  && ((unsigned char)raw[0] & 0x80) != 0
                  && ((unsigned char)raw[0] & 0x7F) >= 1
                  && ((unsigned char)raw[0] & 0x7F) <= 4;

    if (!is_mixstr) {
        DumpRawString(out, str);
        return;
    }

    /* Decrypt: skip the marker byte, AES-CTR with nonce[15]=2 */
    std::string value = raw.substr(1);
    unsigned char nonce[16] = {0};
    memcpy(nonce, mod->pyarmor_mix_str_aes_nonce, 12);
    nonce[15] = 2;
    plusaes::crypt_ctr(
        reinterpret_cast<unsigned char*>(&value[0]),
        value.length(),
        mod->pyarmor_aes_key,
        16,
        &nonce);

    /* marker byte low bit: 1 = unicode, 0 = bytes */
    int write_type = ((unsigned char)raw[0] & 1) ? PycObject::TYPE_UNICODE
                                                 : PycObject::TYPE_STRING;
    out.put((char)write_type);
    put32(out, (unsigned int)value.size());
    out.write(value.data(), (std::streamsize)value.size());
}

/* ---- main object dispatcher ---- */

void DumpObject(std::ostream& out, PycRef<PycObject> obj, PycModule* mod, bool mix_str)
{
    if (obj == NULL) {
        /* NULL is the dict terminator; write '0' */
        out.put(PycObject::TYPE_NULL);
        return;
    }

    int t = obj->type();

    switch (t) {
    case PycObject::TYPE_NULL:
        out.put(PycObject::TYPE_NULL);
        break;

    case PycObject::TYPE_NONE:
        out.put(PycObject::TYPE_NONE);
        break;

    case PycObject::TYPE_FALSE:
        out.put(PycObject::TYPE_FALSE);
        break;

    case PycObject::TYPE_TRUE:
        out.put(PycObject::TYPE_TRUE);
        break;

    case PycObject::TYPE_STOPITER:
        out.put(PycObject::TYPE_STOPITER);
        break;

    case PycObject::TYPE_ELLIPSIS:
        out.put(PycObject::TYPE_ELLIPSIS);
        break;

    case PycObject::TYPE_INT:
        out.put(PycObject::TYPE_INT);
        put32(out, (unsigned int)obj.cast<PycInt>()->value());
        break;

    case PycObject::TYPE_INT64:
        {
            /* Reconstruct two int32 halves from the four 15-bit digits stored
             * by PycLong::load(TYPE_INT64). */
            out.put(PycObject::TYPE_INT64);
            const std::vector<int>& v = obj.cast<PycLong>()->value();
            unsigned int lo = ((unsigned int)v[0] & 0xFFFF)
                            | (((unsigned int)v[1] & 0xFFFF) << 16);
            unsigned int hi = ((unsigned int)v[2] & 0xFFFF)
                            | (((unsigned int)v[3] & 0xFFFF) << 16);
            put32(out, lo);
            put32(out, hi);
        }
        break;

    case PycObject::TYPE_LONG:
        {
            auto lng = obj.cast<PycLong>();
            out.put(PycObject::TYPE_LONG);
            put32(out, (unsigned int)lng->size()); /* signed: negative = negative number */
            int actualSize = lng->size() >= 0 ? lng->size() : -lng->size();
            for (int i = 0; i < actualSize; i++)
                put16(out, (unsigned int)lng->value()[i]);
        }
        break;

    case PycObject::TYPE_FLOAT:
        {
            auto flt = obj.cast<PycFloat>();
            out.put(PycObject::TYPE_FLOAT);
            int len = (int)strlen(flt->value());
            out.put((char)len);
            out.write(flt->value(), len);
        }
        break;

    case PycObject::TYPE_BINARY_FLOAT:
        out.put(PycObject::TYPE_BINARY_FLOAT);
        put64(out, obj.cast<PycCFloat>()->value());
        break;

    case PycObject::TYPE_COMPLEX:
        {
            auto cx = obj.cast<PycComplex>();
            out.put(PycObject::TYPE_COMPLEX);
            int rlen = (int)strlen(cx->value());
            out.put((char)rlen);
            out.write(cx->value(), rlen);
            int ilen = (int)strlen(cx->imag());
            out.put((char)ilen);
            out.write(cx->imag(), ilen);
        }
        break;

    case PycObject::TYPE_BINARY_COMPLEX:
        {
            auto cx = obj.cast<PycCComplex>();
            out.put(PycObject::TYPE_BINARY_COMPLEX);
            put64(out, cx->value());
            put64(out, cx->imag());
        }
        break;

    case PycObject::TYPE_STRING:
    case PycObject::TYPE_INTERNED:
    case PycObject::TYPE_UNICODE:
    case PycObject::TYPE_ASCII:
    case PycObject::TYPE_ASCII_INTERNED:
    case PycObject::TYPE_SHORT_ASCII:
    case PycObject::TYPE_SHORT_ASCII_INTERNED:
        if (mix_str)
            DumpMixStr(out, obj.cast<PycString>(), mod);
        else
            DumpRawString(out, obj.cast<PycString>());
        break;

    case PycObject::TYPE_TUPLE:
    case PycObject::TYPE_SMALL_TUPLE:
        {
            auto seq = obj.cast<PycTuple>();
            if (t == PycObject::TYPE_SMALL_TUPLE) {
                out.put(PycObject::TYPE_SMALL_TUPLE);
                out.put((char)(seq->size() & 0xFF));
            } else {
                out.put(PycObject::TYPE_TUPLE);
                put32(out, (unsigned int)seq->size());
            }
            for (const auto& item : seq->values())
                DumpObject(out, item, mod, mix_str);
        }
        break;

    case PycObject::TYPE_LIST:
        {
            auto seq = obj.cast<PycList>();
            out.put(PycObject::TYPE_LIST);
            put32(out, (unsigned int)seq->size());
            for (const auto& item : seq->values())
                DumpObject(out, item, mod, mix_str);
        }
        break;

    case PycObject::TYPE_SET:
    case PycObject::TYPE_FROZENSET:
        {
            auto seq = obj.cast<PycSet>();
            out.put((char)t);
            put32(out, (unsigned int)seq->size());
            for (const auto& item : seq->values())
                DumpObject(out, item, mod, mix_str);
        }
        break;

    case PycObject::TYPE_DICT:
        {
            auto dict = obj.cast<PycDict>();
            out.put(PycObject::TYPE_DICT);
            for (const auto& kv : dict->values()) {
                DumpObject(out, std::get<0>(kv), mod, mix_str);
                DumpObject(out, std::get<1>(kv), mod, mix_str);
            }
            out.put(PycObject::TYPE_NULL); /* NULL terminator */
        }
        break;

    case PycObject::TYPE_CODE:
    case PycObject::TYPE_CODE2:
        DumpCode(out, obj.cast<PycCode>(), mod);
        break;

    default:
        fprintf(stderr, "DumpObject: unsupported type 0x%X\n", t);
        break;
    }
}

/* ---- code object serializer ---- */

static void DumpCode(std::ostream& out, PycRef<PycCode> code, PycModule* mod)
{
    /* Preserve original type tag ('c' vs 'C' for Python 1.0-1.2) */
    out.put((char)code->type());

    /* argcount — 1.3+: short; 2.3+: int */
    if (mod->verCompare(1, 3) >= 0 && mod->verCompare(2, 3) < 0)
        put16(out, (unsigned int)code->argCount());
    else if (mod->verCompare(2, 3) >= 0)
        put32(out, (unsigned int)code->argCount());

    /* posonlyargcount — 3.8+ */
    if (mod->verCompare(3, 8) >= 0)
        put32(out, (unsigned int)code->posOnlyArgCount());

    /* kwonlyargcount — 3.0+ */
    if (mod->majorVer() >= 3)
        put32(out, (unsigned int)code->kwOnlyArgCount());

    /* nlocals — 1.3-2.2: short; 2.3-3.10: int; 3.11+: absent */
    if (mod->verCompare(1, 3) >= 0 && mod->verCompare(2, 3) < 0)
        put16(out, (unsigned int)code->numLocals());
    else if (mod->verCompare(2, 3) >= 0 && mod->verCompare(3, 11) < 0)
        put32(out, (unsigned int)code->numLocals());

    /* stacksize — 1.5-2.2: short; 2.3+: int */
    if (mod->verCompare(1, 5) >= 0 && mod->verCompare(2, 3) < 0)
        put16(out, (unsigned int)code->stackSize());
    else if (mod->verCompare(2, 3) >= 0)
        put32(out, (unsigned int)code->stackSize());

    /* flags — 1.3+: reverse the Pyarmor remap and strip CO_OBFUSCATED */
    if (mod->verCompare(1, 3) >= 0) {
        unsigned int flags = (unsigned int)code->flags();

        if (mod->verCompare(3, 8) < 0) {
            /* Reverse the remap applied during load() in pyc_code.cpp.
             * Authoritative formula from pycdas.cpp line 116:
             *   orig = (flags & 0x1FFF) | ((flags & 0xDFFE0000) >> 4) | (flags & 0x20000000)
             * 0xDFFE0000 = bits 17-31 excluding bit 29 (CO_PYARMOR). */
            flags = (flags & 0x1FFF)
                  | ((flags & 0xDFFE0000u) >> 4)
                  | (flags & 0x20000000u);
        }
        /* Strip Pyarmor obfuscation flag — must not appear in a clean .pyc */
        flags &= ~(unsigned int)PycCode::CO_PYARMOR_OBFUSCATED;

        if (mod->verCompare(2, 3) < 0)
            put16(out, flags);
        else
            put32(out, flags);
    }

    /* co_code — binary bytecode; already decrypted by pyarmorDecryptCoCode */
    DumpRawString(out, code->code());

    /* co_consts — mix_str applies to string constants */
    DumpObject(out, code->consts().try_cast<PycObject>(), mod, /*mix_str=*/true);

    /* co_names */
    DumpObject(out, code->names().try_cast<PycObject>(), mod, /*mix_str=*/false);

    /* co_varnames / locals+names — 1.3+ */
    if (mod->verCompare(1, 3) >= 0)
        DumpObject(out, code->localNames().try_cast<PycObject>(), mod, /*mix_str=*/false);

    /* co_localkinds — 3.11+ binary kind bytes */
    if (mod->verCompare(3, 11) >= 0)
        DumpRawString(out, code->localKinds());

    /* co_freevars / co_cellvars — 2.1-3.10 */
    if (mod->verCompare(2, 1) >= 0 && mod->verCompare(3, 11) < 0) {
        DumpObject(out, code->freeVars().try_cast<PycObject>(), mod, /*mix_str=*/false);
        DumpObject(out, code->cellVars().try_cast<PycObject>(), mod, /*mix_str=*/false);
    }

    /* co_filename, co_name */
    DumpRawString(out, code->fileName());
    DumpRawString(out, code->name());

    /* co_qualname — 3.11+ */
    if (mod->verCompare(3, 11) >= 0)
        DumpRawString(out, code->qualName());

    /* co_firstlineno — 1.5-2.2: short; 2.3+: int */
    if (mod->verCompare(1, 5) >= 0 && mod->verCompare(2, 3) < 0)
        put16(out, (unsigned int)code->firstLine());
    else if (mod->verCompare(2, 3) >= 0)
        put32(out, (unsigned int)code->firstLine());

    /* co_lnotab / co_linetable — 1.5+ binary data */
    if (mod->verCompare(1, 5) >= 0)
        DumpRawString(out, code->lnTable());

    /* co_exceptiontable — 3.11+ binary varint-encoded data */
    if (mod->verCompare(3, 11) >= 0)
        DumpRawString(out, code->exceptTable());

    /* Note: Pyarmor extra fields (the extra_length block after the standard
     * fields in pyc_code.cpp) are NOT written — they were only present when
     * CO_PYARMOR_OBFUSCATED was set, which we've now stripped. */
}

/* ---- .pyc header / entry point ---- */

static unsigned int getMagic(PycModule* mod)
{
    /* Unicode-mode variants for Python 1.6-2.7 are magic+1.
     * mod->isUnicode() reflects whether unicode mode was active. */
    int extra = (mod->verCompare(1, 6) >= 0 && mod->verCompare(3, 0) < 0
                 && mod->isUnicode()) ? 1 : 0;

    switch (mod->majorVer() * 100 + mod->minorVer()) {
    case 100: return MAGIC_1_0;
    case 101: return MAGIC_1_1;
    case 103: return MAGIC_1_3;
    case 104: return MAGIC_1_4;
    case 105: return MAGIC_1_5;
    case 106: return MAGIC_1_6 + extra;
    case 200: return MAGIC_2_0 + extra;
    case 201: return MAGIC_2_1 + extra;
    case 202: return MAGIC_2_2 + extra;
    case 203: return MAGIC_2_3 + extra;
    case 204: return MAGIC_2_4 + extra;
    case 205: return MAGIC_2_5 + extra;
    case 206: return MAGIC_2_6 + extra;
    case 207: return MAGIC_2_7 + extra;
    case 300: return MAGIC_3_0 + 1; /* Python 3.x always unicode */
    case 301: return MAGIC_3_1 + 1;
    case 302: return MAGIC_3_2;     /* 3.2 drops the +1 convention */
    case 303: return MAGIC_3_3;
    case 304: return MAGIC_3_4;
    case 305: return MAGIC_3_5_3;   /* use the later 3.5 magic */
    case 306: return MAGIC_3_6;
    case 307: return MAGIC_3_7;
    case 308: return MAGIC_3_8;
    case 309: return MAGIC_3_9;
    case 310: return MAGIC_3_10;
    case 311: return MAGIC_3_11;
    case 312: return MAGIC_3_12;
    case 313: return MAGIC_3_13;
    case 314: return MAGIC_3_14;
    default:  return 0;
    }
}

void SaveAsPyc(std::ostream& out, PycModule* mod)
{
    unsigned int magic = getMagic(mod);
    if (magic == 0) {
        fprintf(stderr, "SaveAsPyc: unsupported Python version %d.%d\n",
                mod->majorVer(), mod->minorVer());
        return;
    }

    /* Magic number (4 bytes LE) */
    put32(out, magic);

    /* Version-specific header fields (mirrors PycModule::loadFromFile) */
    if (mod->verCompare(3, 7) >= 0) {
        put32(out, 0); /* flags: 0 = timestamp-based validation (no hash) */
        put32(out, 0); /* timestamp */
        put32(out, 0); /* source size */
    } else if (mod->verCompare(3, 3) >= 0) {
        put32(out, 0); /* timestamp */
        put32(out, 0); /* source size (added in 3.3) */
    } else {
        put32(out, 0); /* timestamp */
    }

    /* Marshalled code object */
    DumpObject(out, mod->code().try_cast<PycObject>(), mod, /*mix_str=*/true);
}
