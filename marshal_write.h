#ifndef _MARSHAL_WRITE_H
#define _MARSHAL_WRITE_H

#include "pyc_object.h"
#include "pyc_module.h"
#include <ostream>

/**
 * Serialize a PycObject tree back to Python marshal binary format.
 *
 * @param out       Output stream opened in binary mode (std::ios::binary).
 * @param obj       Object to serialize.
 * @param mod       Module context (provides version info and Pyarmor keys).
 * @param mix_str   If true, decrypt Pyarmor mix_str-encrypted string constants.
 *                  Pass false for binary fields (co_code, lntable, names, etc.)
 */
void DumpObject(std::ostream& out, PycRef<PycObject> obj, PycModule* mod,
                bool mix_str = true);

/**
 * Write a complete .pyc file to the output stream.
 * Writes the version-specific .pyc header followed by the marshalled code object.
 * Pyarmor-specific flags are stripped and encrypted bytecode/strings are restored.
 *
 * @param out  Output stream opened in binary mode (std::ios::binary).
 * @param mod  Loaded module (must have been loaded via loadFromOneshotSequenceFile).
 */
void SaveAsPyc(std::ostream& out, PycModule* mod);

#endif
