//
// Created by Vavaldi on 14-8-2021.
//

#ifndef FIRSTPROJECT_RULE_H
#define FIRSTPROJECT_RULE_H


#include <string>
#include <functional>
#include <algorithm>

class Rule {
public:
    // Per-candidate state shared by the rules of a single rule line,
    // mirroring hashcat's memory rules (M, X, 4, 6, Q). A fresh Context is
    // created for every word each rule set is applied to.
    struct Context {
        std::string memory;      // word saved by the 'M' (memorize) rule
        bool memory_set = false;
    };

    char rule;
    std::string rule_value_1;
    std::string rule_value_2;
    std::function<void(std::string &, Context &)> rule_processor;
    bool invalid_rule;

    Rule(char input_rule, const std::string &input_rule_value_1, const std::string &input_rule_value_2);
    std::string print(int output_channel=0, bool hashcat_output = false);
    void process(std::string& plaintext, Context& ctx);
    std::function<void(std::string&, Context&)> build_rule_processor();
    bool operator==(const Rule& rhs) const;

    static int rule_identify(char);

private:
    [[nodiscard]] bool validate_rule() const;
};

#endif //FIRSTPROJECT_RULE_H
