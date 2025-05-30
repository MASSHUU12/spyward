module ini;

import std.stdio : stderr;
import std.string : split, splitLines, strip, startsWith, endsWith;
import std.conv : to;
import std.variant : Variant;

/// Represents a typed field in the INI structure
struct FieldSpec(T)
{
    string key;
    bool required;
    T defaultValue;
}

/// A specification for an entire section, including its fields
struct SectionSpec(Fields...)
{
    string name;
    alias Fields = fields;
}

/// Represents a single section read from the INI
struct IniSection
{
    string name;
    string[string] entries;
    Variant[string] typedEntries;
}

/// Parser that validates against given section specs
struct IniParser(Sections...)
{
    IniSection[] sections;

    this(string data)
    {
        parse(data);
        validateSections();
    }

    string stripComments(string s)
    {
        size_t pos = s.indexOfAny([";", "#"]);
        return pos == typeid(size_t).init ? s : s[0 .. pos];
    }

    void parse(string data) pure @safe
    {
        IniSection* current;

        foreach (line; data.splitLines())
        {
            string noCmt = stripComments(line).strip;
            if (noCmt.length == 0)
                continue;

            if (noCmt.startsWith('[') && noCmt.endsWith(']'))
            {
                sections ~= IniSection(noCmt[1 .. $ - 1]);
                current = &sections[$ - 1];
            }
            else if (current && noCmt.contains('='))
            {
                string kv = noCmt.split("=", 2);
                if (kv.length == 2)
                {
                    string key = kv[0].strip();
                    string val = kv[1].strip();
                    current.entries[key] = val;
                }
            }
        }
    }

    void validateSections() pure @safe
    {
        static foreach (spec; Sections)
        {
            bool found;
            foreach (ref actual; sections)
            {
                if (actual.name == spec.name)
                {
                    found = true;
                    validateFields!(spec)(actual);
                    break;
                }
            }

            if (!found)
            {
                stderr.writeln("Missing expected section: ", spec.name);
            }
        }
    }

    void validateFields(SectionSpec)(ref IniSection actualSection) pure @safe
    {
        foreach (field; SectionSpec.fields)
        {
            if (actualSection.entries.containsKey(field.key))
            {
                string val = actualSection.entries[field.key];
                try
                {
                    auto converted = to!(typeof(field.T)(val));
                    actualSection.typedEntries[field.key] = converted;
                }
                catch (Exception e)
                {
                    stderr.writeln("Error converting key '", field.key, "' in section [", actualSection.name,
                        "] to ", typeof(field.T).stringof, ": ", e.msg);
                }
            }
            else
            {
                if (field.required)
                {
                    stderr.writeln("Missing required key '", field.key, "' in section [", actualSection.name, "]");
                }
                actualSection.typedEntries[field.key] = field.defaultValue;
            }
        }
    }
}
