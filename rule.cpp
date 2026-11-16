//
// Created by Vavaldi on 14-8-2021.
//

#include "rule.h"
#include <cctype>
#include <iostream>


Rule::Rule(const char input_rule, const std::string& input_rule_value_1, const std::string& input_rule_value_2) {
    rule_value_1 = input_rule_value_1;
    rule_value_2 = input_rule_value_2;
    rule = input_rule;
    invalid_rule = !validate_rule();
    if(invalid_rule) {
        // Syntactically invalid rules are discarded downstream; skip building the processor.
        rule_processor = [](std::string&, Context&){};
        return;
    }
    rule_processor = build_rule_processor(); // may set invalid_rule = true
}

bool Rule::operator==(const Rule& rhs) const
{
    return (rule == rhs.rule) && (rule_value_1 == rhs.rule_value_1) && (rule_value_2 == rhs.rule_value_2);
    // or, in C++11 (must #include <tuple>)
    // return std::tie(apple, banana) == std::tie(rhs.apple, rhs.banana);
}

int Rule::rule_identify(char rule_char) {
    switch(rule_char) {
        case ':':
        case 'l':
        case 'u':
        case 'c':
        case 'C':
        case 't':
        case 'r':
        case 'd':
        case 'f':
        case '{':
        case '}':
        case '[':
        case ']':
        case 'k':
        case 'K':
        case 'q':
        case 'E':
        case 'a':  // toggle case recursively (unimplemented no-op in hashcat too)
        case 'M':  // memorize word
        case '4':  // append word saved to memory
        case '6':  // prepend word saved to memory
        case 'Q':  // reject if word equals word saved to memory
        case 'h':  // convert word to lowercase hex
        case 'H':  // convert word to uppercase hex
            return 1;
        case '@':
        case 'T':
        case 'p':
        case 'D':
        case 'Z':
        case 'z':
        case '$':
        case '^':
        case '<':
        case '>':
        case '_':
        case '\'':
        case '!':
        case '/':
        case '(':
        case ')':
        case 'y':
        case 'Y':
        case '-':
        case '+':
        case 'e':
        case '.':
        case ',':
        case 'L':
        case 'R':
            return 2;
        case 's':
        case 'S':
        case 'x':
        case 'O':
        case 'o':
        case 'i':
        case '3':
        case '*':
        case '=':  // reject unless char at N is X
        case '%':  // reject unless char X occurs at least N times
        case 'B':  // add char C to char at N
        case 'v':  // insert char X every N characters
        case 'N':  // replace Nth occurrence of X with Y
        case 'X':  // insert substring of memory
        case '~':  // character class rules (hashcat 7+)
            return 3;
        default:
            return -1;
    }
}

bool Rule::validate_rule() const {
    switch(rule) {
        case ':': return true;
        case 'l':
        case 'u':
        case 'c':
        case 'C':
        case 't':
        case 'r':
        case 'd':
        case 'f':
        case '{':
        case '}':
        case '[':
        case ']':
        case 'k':
        case 'K':
        case 'q':
        case 'E':
        case 'a':
        case 'M':
        case '4':
        case '6':
        case 'Q':
        case 'h':
        case 'H':
            if(!(rule_value_1.empty() && rule_value_2.empty())) { // Unary operations should not have rule values.
                return false;
            }
            return true;
        case 'S': // bare 'S' = shift case (hashcat 8.0.0, unary); 'SXY' = replace first occurrence (ruleprocessorY extension)
            return (rule_value_1.empty() && rule_value_2.empty()) || (!rule_value_1.empty() && !rule_value_2.empty());
        case '@':
        case 'T':
        case 'p':
        case 'D':
        case 'Z':
        case 'z':
        case '$':
        case '^':
        case '<':
        case '>':
        case '_':
        case '\'':
        case '!':
        case '/':
        case '(':
        case ')':
        case 'y':
        case 'Y':
        case '-':
        case '+':
        case 'e':
        case '.':
        case ',':
        case 'L':
        case 'R':
            if(rule_value_1.empty() || !rule_value_2.empty()) { // Binary operations should not have 2 rule values.
                return false;
            }
            return true;
        case 's':
        case 'x':
        case 'O':
        case 'o':
        case 'i':
        case '3':
        case '*':
        case '=':
        case '%':
        case 'B':
        case 'v':
        case 'N':
        case 'X':
        case '~':
            if(rule_value_1.empty() || rule_value_2.empty()) {
                return false;
            }
            return true;
        default:
            return false;
    }
}

std::function<void(std::string&, Rule::Context&)> Rule::build_rule_processor() {
    int int_value_1, int_value_2;
    bool value_1_is_numeric = (!rule_value_1.empty() && rule_value_1.find_first_not_of("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") == std::string::npos);
    bool value_2_is_numeric = (!rule_value_2.empty() && rule_value_2.find_first_not_of("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") == std::string::npos);

    auto get_number_value = [](const std::string& value)
    {
        std::string alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        size_t index = alphabet.find(value[0]);
        return static_cast<int>(index);
    };

    // Character class matching used by the '~' rules (hashcat 7+).
    // Classes: l=lowercase, u=uppercase, d=digit, h=lowercase hex, H=uppercase hex, s=symbol, ?=literal '?'
    auto class_match = [](char c, char cls) -> bool
    {
        const auto uc = static_cast<unsigned char>(c);
        switch(cls) {
            case 'l': return islower(uc) != 0;
            case 'u': return isupper(uc) != 0;
            case 'd': return isdigit(uc) != 0;
            case 'h': return isdigit(uc) != 0 || (uc >= 'a' && uc <= 'f');
            case 'H': return isdigit(uc) != 0 || (uc >= 'A' && uc <= 'F');
            case 's': return uc == ' ' || (uc >= '!' && uc <= '/') || (uc >= ':' && uc <= '@') || (uc >= '[' && uc <= '`') || (uc >= '{' && uc <= '~');
            case '?': return c == '?';
            default: return false;
        }
    };


    switch(rule) {
        case ':':
            return [](std::string& plaintext, Context&){};
        case 'a':  // toggle case recursively — unimplemented no-op in hashcat as well
            return [](std::string& plaintext, Context&){};
        case 'l':
            return [](std::string& plaintext, Context&){
                transform(plaintext.begin(), plaintext.end(), plaintext.begin(), ::tolower);
            };

        case 'u':
            return [](std::string& plaintext, Context&){
                transform(plaintext.begin(), plaintext.end(), plaintext.begin(), ::toupper);
            };

        case 'c':
            return [](std::string& plaintext, Context&){
                if(plaintext.empty()) return;
                transform(plaintext.begin(), plaintext.end(), plaintext.begin(), ::tolower);
                plaintext[0] = char(toupper(plaintext[0]));
            };

        case 'C':
            return [](std::string& plaintext, Context&){
                if(plaintext.empty()) return;
                transform(plaintext.begin(), plaintext.end(), plaintext.begin(), ::toupper);
                plaintext[0] = char(tolower(plaintext[0]));
            };

        case 't':
            return [](std::string& plaintext, Context&){
                for (char& i : plaintext) {
                    if(islower(static_cast<unsigned char>(i))) {
                        i = char(toupper(i));
                    } else if (isupper(static_cast<unsigned char>(i))) {
                        i = char(tolower(i));
                    }
                }
            };

        case 'q':
            return [](std::string& plaintext, Context&){
                for(std::string::size_type i = 0; i < plaintext.size(); ++i) {
                    plaintext.insert(i+1, 1, plaintext[i]);
                    i++;
                }
            };

        case 'r':
            return [](std::string& plaintext, Context&){
                reverse(plaintext.begin(), plaintext.end());
            };

        case 'k':
            return [](std::string& plaintext, Context&){
                if(plaintext.length() < 2) return;
                char i = plaintext[0];
                plaintext[0] = plaintext[1];
                plaintext[1] = i;
            };

        case 'K':
            return [](std::string& plaintext, Context&){
                if(plaintext.length() < 2) return;
                std::swap(plaintext[plaintext.length()-1], plaintext[plaintext.length()-2]);
            };

        case 'd':
            return [](std::string& plaintext, Context&){
                plaintext += plaintext;
            };

        case 'f':
            return [](std::string& plaintext, Context&){
                std::string copy = plaintext; // Extra copy for operations
                reverse(copy.begin(), copy.end());
                plaintext += copy;
            };

        case '{':
            return [](std::string& plaintext, Context&){
                if(plaintext.empty()) return;
                plaintext += plaintext[0];
                plaintext.erase(0,1);

            };

        case '}':
            return [](std::string& plaintext, Context&){
                if(plaintext.empty()) return;
                plaintext.insert(0, 1, plaintext.back());
                plaintext.pop_back();
            };

        case '[':
            return [](std::string& plaintext, Context&){
                plaintext.erase(0, 1);
            };

        case ']':
            return [](std::string& plaintext, Context&){
		        if(plaintext.empty()) return;
                plaintext.erase(plaintext.size()-1, 1);
            };
        case 'E':  // title case with space separator (hashcat 8.0.0 semantics: separator keeps its case, a run counts once)
            return [](std::string& plaintext, Context&){
                bool upper_next = true;
                for(char& c : plaintext) {
                    if(c == ' ') {
                        upper_next = true;
                        continue;
                    }
                    if(upper_next) {
                        c = char(toupper(static_cast<unsigned char>(c)));
                        upper_next = false;
                    } else {
                        c = char(tolower(static_cast<unsigned char>(c)));
                    }
                }
                if(!plaintext.empty()) plaintext[0] = char(toupper(static_cast<unsigned char>(plaintext[0])));
            };

        case 'T':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // character location
            return [char_location = int_value_1](std::string& plaintext, Context&){
                if(plaintext.empty() || char_location > plaintext.size()-1) {
                    return;
                }
                if(islower(static_cast<unsigned char>(plaintext[char_location]))) {
                    plaintext[char_location] = char(toupper(plaintext[char_location]));
                } else if (isupper(static_cast<unsigned char>(plaintext[char_location]))) {
                    plaintext[char_location] = char(tolower(plaintext[char_location]));
                }
            };

        case 'p':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1);
            return [duplicate_count=int_value_1](std::string& plaintext, Context&){
                std::string copy = plaintext;
                for(int i=0; i < duplicate_count; i++) {
                    plaintext += copy;
                }
            };

        case 'D':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // character location
            if(int_value_1 < 0) {
                break;
            }
            return [char_location=int_value_1](std::string& plaintext, Context&){
                if(plaintext.empty() || char_location > plaintext.size()-1) {
                    return;
                }
                plaintext.erase(char_location, 1);
            };

        case 'z':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // duplicate amount
            return [duplicate_count=int_value_1](std::string& plaintext, Context&){
                for(int i=0; i < duplicate_count; i++) {
                    plaintext.insert(0, plaintext.substr(0,1));
                }
            };

        case 'Z':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // duplicate amount
            return [duplicate_count=int_value_1](std::string& plaintext, Context&){
                if(plaintext.empty()) return;
                for(int i=0; i < duplicate_count; i++) {
                    plaintext += plaintext.substr(plaintext.size()-1, 1);
                }
            };

        case '\'':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // duplicate amount
            if(int_value_1 < 0) {
                break;
            }
            return [duplicate_count=int_value_1](std::string& plaintext, Context&){
                if(plaintext.empty() || duplicate_count > plaintext.size()-1) {
                    return;
                }
                plaintext = plaintext.substr(0, duplicate_count);
            };

        case 's':
            if(rule_value_1.size() == 1 && rule_value_2.size() == 1) {
                return [rule_value_1=rule_value_1[0], rule_value_2=rule_value_2[0]](std::string& plaintext, Context&){
                    std::replace(plaintext.begin(), plaintext.end(), rule_value_1, rule_value_2);
                };
            } else {
                return [rule_value_1=rule_value_1, rule_value_2=rule_value_2](std::string& plaintext, Context&){
                    size_t index = 0;
                    while(true) {
                        index = plaintext.find(rule_value_1, index);
                        if(index == std::string::npos) break;
                        plaintext = plaintext.replace(index, rule_value_1.size(), rule_value_2);
                        index += rule_value_2.size();
                    }
                };
            }

        case 'S':
            if(rule_value_1.empty() && rule_value_2.empty()) {
                // hashcat 8.0.0: shift the case of each char (JtR-like), incl. shifted symbols ('1' <-> '!' etc.)
                static const unsigned char cshift_lookup[256] = {
                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                    0,16,5,16,16,16,17,5,17,25,18,22,16,114,16,16,
                    25,16,114,16,16,16,104,17,18,17,1,1,16,22,16,16,
                    114,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,
                    32,32,32,32,32,32,32,32,32,32,32,32,32,32,104,114,
                    30,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,
                    32,32,32,32,32,32,32,32,32,32,32,32,32,32,30,0,
                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
                };
                return [](std::string& plaintext, Context&){
                    for(char& c : plaintext) {
                        const auto uc = static_cast<unsigned char>(c);
                        c = static_cast<char>(uc ^ cshift_lookup[uc]);
                    }
                };
            }
            // ruleprocessorY extension: SXY replaces only the first occurrence of X with Y
            return [rule_value_1=rule_value_1, rule_value_2=rule_value_2](std::string& plaintext, Context&){
                if(plaintext.find(rule_value_1) != std::string::npos) {
                    plaintext = plaintext.replace(plaintext.find(rule_value_1), rule_value_1.size(), rule_value_2);
                }
            };

        case '$':
            return [rule_value_1=rule_value_1](std::string& plaintext, Context&){
                plaintext.append(rule_value_1);
            };

        case '^':
            return [rule_value_1=rule_value_1](std::string& plaintext, Context&){
                plaintext.insert(0, rule_value_1);
            };

        case 'y':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // insert location
            if(int_value_1 == 0) break;
            return [rule_value_1=int_value_1](std::string& plaintext, Context&){
                plaintext.insert(0, plaintext.substr(0, rule_value_1));
            };

        case 'Y':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // insert location
            if(int_value_1 == 0) break;
            return [rule_value_1=int_value_1](std::string& plaintext, Context&){
                if(rule_value_1 > plaintext.size()) {
                    plaintext += plaintext;
                } else {
                    plaintext += plaintext.substr(plaintext.size() - rule_value_1);
                }
            };

        case 'L':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // insert location
            return [rule_value_1=int_value_1](std::string& plaintext, Context&){
                if(rule_value_1 >= plaintext.size()) return;
                plaintext[rule_value_1] = static_cast<char>(static_cast<unsigned char>(plaintext[rule_value_1]) << 1);
            };

        case 'R':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // insert location
            return [rule_value_1=int_value_1](std::string& plaintext, Context&){
                if(rule_value_1 >= plaintext.size()) return;
                plaintext[rule_value_1] = static_cast<char>(static_cast<unsigned char>(plaintext[rule_value_1]) >> 1);
            };

        case '-':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // insert location
            return [rule_value_1=int_value_1](std::string& plaintext, Context&) {
                if(rule_value_1 >= plaintext.size()) return;
                plaintext[rule_value_1] = --plaintext[rule_value_1];
            };

        case '+':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // insert location
            return [rule_value_1=int_value_1](std::string& plaintext, Context&) {
                if(rule_value_1 >= plaintext.size()) return;
                plaintext[rule_value_1] = ++plaintext[rule_value_1];
            };

        case '@':
            return [rule_value_1=rule_value_1](std::string& plaintext, Context&){
                plaintext.erase(std::remove(plaintext.begin(), plaintext.end(), rule_value_1[0]), plaintext.end());
            };

        case '.':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // target location
            return [rule_value_1=int_value_1](std::string& plaintext, Context&){
                if(rule_value_1+1 >= plaintext.size()) return;
                plaintext[rule_value_1] = plaintext[rule_value_1+1];
            };

        case ',':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // target location
            return [rule_value_1=int_value_1](std::string& plaintext, Context&){
                if(rule_value_1 < plaintext.size() && rule_value_1 > 0) {
                    plaintext[rule_value_1] = plaintext[rule_value_1-1];
                }
            };

        case 'e':  // title case with separator X (hashcat 8.0.0 semantics: separator keeps its case, a run counts once)
            return [rule_value_1=rule_value_1](std::string& plaintext, Context&){
                if(rule_value_1.empty()) return;
                bool upper_next = true;
                for(char& c : plaintext) {
                    if(c == rule_value_1[0]) {
                        upper_next = true;
                        continue;
                    }
                    if(upper_next) {
                        c = char(toupper(static_cast<unsigned char>(c)));
                        upper_next = false;
                    } else {
                        c = char(tolower(static_cast<unsigned char>(c)));
                    }
                }
                if(!plaintext.empty()) plaintext[0] = char(toupper(static_cast<unsigned char>(plaintext[0])));
            };

        case 'i':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // insert location
            return [insert_location=int_value_1, rule_value_2=rule_value_2](std::string& plaintext, Context&) {
                if(plaintext.empty() || insert_location > plaintext.size()) return;
                plaintext.insert(insert_location, rule_value_2);
            };

        case 'O':
            if(!value_1_is_numeric || !value_2_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // start location
            int_value_2 = get_number_value(rule_value_2); // delete amount
            return [start_loc=int_value_1, delete_amount=int_value_2](std::string& plaintext, Context&) {
                if(start_loc > plaintext.size()-1 || plaintext.empty()) return;
                if(start_loc + delete_amount < plaintext.size()) {
                    plaintext.erase(start_loc, delete_amount);
                } else {
//                    plaintext.erase(start_loc, plaintext.size()-start_loc); // Delete until end. // Hashcat behaviour does not delete if it goes out of bound.
                }
            };

        case 'o':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // overwrite location
            if(int_value_1 < 0) break;

            return [offset=int_value_1, replace_value=rule_value_2](std::string& plaintext, Context&){
                if((offset+replace_value.size()-1) > plaintext.size()-1 || plaintext.empty()) return;
                for(int i=0; i < replace_value.size(); i++) {
                    plaintext[offset + i] = replace_value[i];
                }
            };

        case '*':
            if(!value_1_is_numeric || !value_2_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // swap location 1
            int_value_2 = get_number_value(rule_value_2); // swap location 2
            return [swap_1=int_value_1, swap_2=int_value_2](std::string& plaintext, Context&){
                if(plaintext.empty() || swap_1 >= plaintext.size() || swap_2 >= plaintext.size()) return;
                std::swap(plaintext[swap_1], plaintext[swap_2]);
            };

        case 'x':
            if(!value_1_is_numeric || !value_2_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // start location
            int_value_2 = get_number_value(rule_value_2); // delete amount
            if(int_value_1 < 0 || int_value_2 < 0) break;
            return [start_loc=int_value_1, keep_amount=int_value_2](std::string& plaintext, Context&){
                if(plaintext.empty() || start_loc >= plaintext.size()) return;
                if((start_loc + keep_amount) <= plaintext.size()) {
                    plaintext.erase(start_loc + keep_amount, plaintext.size()-(start_loc+keep_amount));
                    plaintext.erase(0, start_loc); // Delete from start to start of rule
                }
            };

        case '<':  // Reject plains if their length is greater than N
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1);
            return [reject_count=int_value_1](std::string& plaintext, Context&){
                if(plaintext.size() <= reject_count) return;
                plaintext = "";
            };

        case '>':  // Reject plains if their length is less than N
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1);
            return [reject_count=int_value_1](std::string& plaintext, Context&){
                if(plaintext.size() >= reject_count) return;
                plaintext = "";
            };

        case '_':  // Reject plains of length not equal to N
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1);
            return [reject_count=int_value_1](std::string& plaintext, Context&){
                if(plaintext.size() != reject_count) {
                    plaintext = "";
                }
            };

        case '!':  // Reject plains which contain rule_value_1
            return [rule_value_1=rule_value_1](std::string& plaintext, Context&){
                if (plaintext.find(rule_value_1) != std::string::npos) {
                    plaintext = "";
                }
            };

        case '/':  // Reject plains which do not contain char X
            return [rule_value_1=rule_value_1](std::string& plaintext, Context&){
                if (plaintext.find(rule_value_1) == std::string::npos) {
                    plaintext = "";
                }
            };

        case '3':  // Toggle letter after nth instance of a char
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // character location
            return [rule_instance_of_char = int_value_1, char_value_rule = rule_value_2](std::string& plaintext, Context&) {
                if(plaintext.empty()) return;
                int n_th_instance_of_char = -1;
                for(char &char_value : plaintext) {
                    if(n_th_instance_of_char == rule_instance_of_char) {
                        if (islower(static_cast<unsigned char>(char_value))) {
                            char_value = char(toupper(char_value));
                        } else if (isupper(static_cast<unsigned char>(char_value))) {
                            char_value = char(tolower(char_value));
                        }
                        return;
                    }
                    if(char_value == char_value_rule[0]) n_th_instance_of_char++;
                }
            };

        case '(':  // Reject plains which do not start with X
            return [rule_value_1=rule_value_1](std::string& plaintext, Context&){
                if(plaintext.compare(0, rule_value_1.size(), rule_value_1) != 0) {
                    plaintext = "";
                }
            };

        case ')':  // Reject plains which do not end with X
            return [rule_value_1=rule_value_1](std::string& plaintext, Context&){
                if(plaintext.size() < rule_value_1.size() ||
                   plaintext.compare(plaintext.size()-rule_value_1.size(), rule_value_1.size(), rule_value_1) != 0) {
                    plaintext = "";
                }
            };

        case '=':  // Reject plains which do not have char X at position N
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // character location
            return [char_location=int_value_1, rule_value_2=rule_value_2](std::string& plaintext, Context&){
                if(char_location+1 > plaintext.size() ||
                   plaintext.compare(char_location, rule_value_2.size(), rule_value_2) != 0) {
                    plaintext = "";
                }
            };

        case '%':  // Reject plains which contain char X less than N times
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // required amount
            return [required_amount=int_value_1, rule_value_2=rule_value_2](std::string& plaintext, Context&){
                if(required_amount+1 > plaintext.size()) {
                    plaintext = "";
                    return;
                }
                size_t occurrence_count = 0;
                size_t index = 0;
                while((index = plaintext.find(rule_value_2, index)) != std::string::npos) {
                    occurrence_count++;
                    index += rule_value_2.size();
                }
                if(occurrence_count < required_amount) {
                    plaintext = "";
                }
            };

        case 'M':  // Memorize current word
            return [](std::string& plaintext, Context& ctx){
                ctx.memory = plaintext;
                ctx.memory_set = true;
            };

        case '4':  // Append the word saved to memory
            return [](std::string& plaintext, Context& ctx){
                if(!ctx.memory_set) {
                    plaintext = "";
                    return;
                }
                plaintext += ctx.memory;
            };

        case '6':  // Prepend the word saved to memory
            return [](std::string& plaintext, Context& ctx){
                if(!ctx.memory_set) {
                    plaintext = "";
                    return;
                }
                plaintext = ctx.memory + plaintext;
            };

        case 'Q':  // Reject plains matching the word saved to memory
            return [](std::string& plaintext, Context& ctx){
                if(ctx.memory_set && plaintext == ctx.memory) {
                    plaintext = "";
                }
            };

        case 'X':  // Insert substring of length M starting at position N of the memorized word at position I
            if(!value_1_is_numeric || rule_value_2.size() != 2) break;
            if(rule_value_2.find_first_not_of("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") != std::string::npos) break;
            int_value_1 = get_number_value(rule_value_1); // start position in memory
            int_value_2 = get_number_value(rule_value_2.substr(0, 1)); // amount of characters to copy
            if(int_value_2 < 1) break;
            {
                int insert_location = get_number_value(rule_value_2.substr(1, 1)); // position in word
                return [mem_start=int_value_1, copy_amount=int_value_2, insert_location](std::string& plaintext, Context& ctx){
                    if(!ctx.memory_set ||
                       insert_location > plaintext.size() ||
                       mem_start > ctx.memory.size() ||
                       mem_start + copy_amount > ctx.memory.size()) {
                        plaintext = "";
                        return;
                    }
                    plaintext.insert(insert_location, ctx.memory.substr(mem_start, copy_amount));
                };
            }

        case 'B':  // Add char C to char at position N
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // character location
            return [char_location=int_value_1, add_value=rule_value_2](std::string& plaintext, Context&){
                if(char_location >= plaintext.size()) return;
                plaintext[char_location] = static_cast<char>(static_cast<unsigned char>(plaintext[char_location]) + static_cast<unsigned char>(add_value[0]));
            };

        case 'h':  // Convert word to lowercase hex
            return [](std::string& plaintext, Context&){
                static const char tbl[] = "0123456789abcdef";
                std::string hex;
                hex.reserve(plaintext.size() * 2);
                for(char c : plaintext) {
                    const auto uc = static_cast<unsigned char>(c);
                    hex += tbl[uc >> 4];
                    hex += tbl[uc & 15];
                }
                plaintext = std::move(hex);
            };

        case 'H':  // Convert word to uppercase hex
            return [](std::string& plaintext, Context&){
                static const char tbl[] = "0123456789ABCDEF";
                std::string hex;
                hex.reserve(plaintext.size() * 2);
                for(char c : plaintext) {
                    const auto uc = static_cast<unsigned char>(c);
                    hex += tbl[uc >> 4];
                    hex += tbl[uc & 15];
                }
                plaintext = std::move(hex);
            };

        case 'v':  // Insert char X every N characters (hashcat 8.0.0: N=0 is valid and a no-op)
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // interval
            return [interval=int_value_1, rule_value_2=rule_value_2](std::string& plaintext, Context&){
                if(interval == 0) return;  // hashcat 8.0.0 mangle_insert_every: upos == 0 leaves the word unchanged
                if(interval >= plaintext.size()+1) return;
                std::string result;
                result.reserve(plaintext.size() + (plaintext.size() / interval + 1) * rule_value_2.size());
                for(size_t i = 0; i < plaintext.size(); i++) {
                    result += plaintext[i];
                    if((i + 1) % interval == 0) {
                        result += rule_value_2;
                    }
                }
                plaintext = std::move(result);
            };

        case 'N':  // Replace the Nth (0-based) occurrence of X with Y
            if(!value_1_is_numeric || rule_value_2.size() < 2) break;
            int_value_1 = get_number_value(rule_value_1); // occurrence
            return [occurrence=int_value_1, old_char=rule_value_2[0], new_value=rule_value_2.substr(1)](std::string& plaintext, Context&){
                int occurrence_count = 0;
                for(size_t i = 0; i < plaintext.size(); i++) {
                    if(plaintext[i] != old_char) continue;
                    if(occurrence_count == occurrence) {
                        plaintext.replace(i, 1, new_value);
                        break;
                    }
                    occurrence_count++;
                }
            };

        case '~': {  // Character class rules: rule_value_1 = sub-operation, rule_value_2 = operands ("?CY", "?C" or "N?C")
            const char sub_op = rule_value_1[0];
            char class_char = 0;
            std::string replace_value;
            bool operands_ok = false;
            bool has_position = (sub_op == '=' || sub_op == '%');
            switch(sub_op) {
                case 's':
                    operands_ok = rule_value_2.size() >= 3 && rule_value_2[0] == '?';
                    class_char = operands_ok ? rule_value_2[1] : 0;
                    replace_value = operands_ok ? rule_value_2.substr(2) : "";
                    break;
                case '@':
                case 'e':
                case '!':
                case '/':
                case '(':
                case ')':
                    operands_ok = rule_value_2.size() >= 2 && rule_value_2[0] == '?';
                    class_char = operands_ok ? rule_value_2[1] : 0;
                    break;
                case '=':
                case '%':
                    operands_ok = rule_value_2.size() >= 3 && rule_value_2[1] == '?' &&
                                  std::string("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ").find(rule_value_2[0]) != std::string::npos;
                    class_char = operands_ok ? rule_value_2[2] : 0;
                    break;
                default:
                    break;
            }
            if(!operands_ok) break;

            switch(sub_op) {
                case 's':  // ~s?CY: replace all characters of class C with Y
                    return [class_char, replace_value, class_match](std::string& plaintext, Context&){
                        std::string result;
                        result.reserve(plaintext.size());
                        for(char c : plaintext) {
                            if(class_match(c, class_char)) {
                                result += replace_value;
                            } else {
                                result += c;
                            }
                        }
                        plaintext = std::move(result);
                    };
                case '@':  // ~@?C: purge all characters of class C
                    return [class_char, class_match](std::string& plaintext, Context&){
                        plaintext.erase(std::remove_if(plaintext.begin(), plaintext.end(),
                            [class_char, class_match](char c){ return class_match(c, class_char); }), plaintext.end());
                    };
                case 'e':  // ~e?C: title case, characters after a run of class C are uppercased
                    return [class_char, class_match](std::string& plaintext, Context&){
                        bool upper_next = true;
                        for(char& c : plaintext) {
                            if(class_match(c, class_char)) {
                                upper_next = true;
                                continue;
                            }
                            if(upper_next) {
                                c = char(toupper(static_cast<unsigned char>(c)));
                                upper_next = false;
                            } else {
                                c = char(tolower(static_cast<unsigned char>(c)));
                            }
                        }
                        if(!plaintext.empty()) plaintext[0] = char(toupper(static_cast<unsigned char>(plaintext[0])));
                    };
                case '!':  // ~!?C: reject plains containing a character of class C
                    return [class_char, class_match](std::string& plaintext, Context&){
                        for(char c : plaintext) {
                            if(class_match(c, class_char)) {
                                plaintext = "";
                                return;
                            }
                        }
                    };
                case '/':  // ~/?C: reject plains not containing a character of class C
                    return [class_char, class_match](std::string& plaintext, Context&){
                        for(char c : plaintext) {
                            if(class_match(c, class_char)) return;
                        }
                        plaintext = "";
                    };
                case '(':  // ~(?C: reject plains whose first character is not in class C
                    return [class_char, class_match](std::string& plaintext, Context&){
                        if(plaintext.empty() || !class_match(plaintext[0], class_char)) {
                            plaintext = "";
                        }
                    };
                case ')':  // ~)?C: reject plains whose last character is not in class C
                    return [class_char, class_match](std::string& plaintext, Context&){
                        if(plaintext.empty() || !class_match(plaintext.back(), class_char)) {
                            plaintext = "";
                        }
                    };
                case '=': {  // ~=N?C: reject plains whose character at position N is not in class C
                    int class_position = get_number_value(rule_value_2.substr(0, 1));
                    return [class_position, class_char, class_match](std::string& plaintext, Context&){
                        if(class_position+1 > plaintext.size() || !class_match(plaintext[class_position], class_char)) {
                            plaintext = "";
                        }
                    };
                }
                case '%': {  // ~%N?C: reject plains with less than N characters of class C
                    int required_amount = get_number_value(rule_value_2.substr(0, 1));
                    return [required_amount, class_char, class_match](std::string& plaintext, Context&){
                        if(required_amount+1 > plaintext.size()) {
                            plaintext = "";
                            return;
                        }
                        int occurrence_count = 0;
                        for(char c : plaintext) {
                            if(class_match(c, class_char)) occurrence_count++;
                        }
                        if(occurrence_count < required_amount) {
                            plaintext = "";
                        }
                    };
                }
                default:
                    break;
            }
            break;
        }
    }

    invalid_rule = true;
    return [](std::string& plaintext, Context&){};
}

void Rule::process(std::string& plaintext, Context& ctx) {
    return rule_processor(plaintext, ctx);
}

std::string Rule::print(int output_channel, bool hashcat_output) {  // 0 = stdout, 1 = error, 2 = return
    std::string rule_1_copy = rule_value_1;
    std::string rule_2_copy = rule_value_2;
    std::string debug_string;

    // Replace tabs with hex encoded tabs
    size_t start_pos = rule_1_copy.find('\t');
    if(start_pos != std::string::npos) {
        rule_1_copy.replace(start_pos, 1, "\\x09");
    }
    start_pos = rule_2_copy.find('\t');
    if(start_pos != std::string::npos) {
        rule_2_copy.replace(start_pos, 1, "\\x09");
    }

    if(hashcat_output) {
        start_pos = rule_1_copy.find(' ');
        if(start_pos != std::string::npos) {
            rule_1_copy.replace(start_pos, 1, "\\x20");
        }
        start_pos = rule_2_copy.find(' ');
        if(start_pos != std::string::npos) {
            rule_2_copy.replace(start_pos, 1, "\\x20");
        }
    }

    switch(Rule::rule_identify(rule)) {
        case 1:
            if (output_channel == 0) {
                std::cout << rule;
            } else if (output_channel == 1) {
                std::cerr << rule;
            } else if (output_channel == 2) {
                debug_string += rule;
            }
            break;
        case 2:
            if (output_channel == 0) {
                std::cout << rule << rule_1_copy;
            } else if (output_channel == 1) {
                std::cerr << rule << rule_1_copy;
            } else if (output_channel == 2) {
                debug_string += rule;
                debug_string += rule_1_copy;
            }
            break;
        case 3:
            if (rule_value_1.size() > 1) {  // if the first rule is multi-byte
                if (!hashcat_output) { // '/' is only a delimiter in the TSV format, not in the hashcat format
                    start_pos = rule_1_copy.find('/');
                    if (start_pos != std::string::npos) {
                        rule_1_copy.replace(start_pos, 1, "\\/");
                    }

                    start_pos = rule_2_copy.find('/');
                    if (start_pos != std::string::npos) {
                        rule_2_copy.replace(start_pos, 1, "\\/");
                    }
                }

                if (output_channel == 0) {
                    std::cout << rule << '/' << rule_1_copy << '/' << rule_2_copy;
                } else if (output_channel == 1) {
                    std::cerr << rule << '/' << rule_1_copy << '/' << rule_2_copy;
                } else if (output_channel == 2) {
                    debug_string += rule;
                    debug_string += '/';
                    debug_string += rule_1_copy;
                    debug_string += '/';
                    debug_string += rule_2_copy;
                }
            } else if (rule_value_2.size() > 1) {  // if the second rule is multi-byte
                if (!hashcat_output) { // '/' is only a delimiter in the TSV format, not in the hashcat format
                    start_pos = rule_1_copy.find('/');
                    if (start_pos != std::string::npos) {
                        rule_1_copy.replace(start_pos, 1, "\\/");
                    }

                    start_pos = rule_2_copy.find('/');
                    if (start_pos != std::string::npos) {
                        rule_2_copy.replace(start_pos, 1, "\\/");
                    }
                }

                if (output_channel == 0) {
                    if (hashcat_output) {
                        std::cout << rule << rule_1_copy << rule_2_copy;
                    } else {
                        std::cout << rule << '/' << rule_1_copy << '/' << rule_2_copy;
                    }
                } else if (output_channel == 1) {
                    if (hashcat_output) {
                        std::cerr << rule << rule_1_copy << rule_2_copy;
                    } else {
                        std::cerr << rule << '/' << rule_1_copy << '/' << rule_2_copy;
                    }
                } else if (output_channel == 2) {
                    debug_string += rule;
                    if (!hashcat_output) debug_string += '/';
                    debug_string += rule_1_copy;
                    if (!hashcat_output) debug_string += '/';
                    debug_string += rule_2_copy;
                }
            } else { // rule 1 is not multi-byte
                if (output_channel == 0) {
                    std::cout << rule << rule_1_copy << rule_2_copy;
                } else if (output_channel == 1) {
                    std::cerr << rule << rule_1_copy << rule_2_copy;
                } else if (output_channel == 2) {
                    debug_string += rule;
                    debug_string += rule_1_copy;
                    debug_string += rule_2_copy;
                }
            }
            break;
    }
    return debug_string;
}


