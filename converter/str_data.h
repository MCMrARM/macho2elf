#include <string>
#include <string_view>
#include <map>

struct StrData {

private:
    std::string data_;
    std::map<std::string, std::size_t, std::less<>> index_map_;

public:
    StrData() {
        data_.push_back(0);
    }

    std::size_t add(std::string_view text) {
        auto it = index_map_.find(text);
        if (it != index_map_.end())
            return it->second;

        auto ret = data_.size();
        index_map_.insert({std::string(text), data_.size()});
        data_.insert(data_.end(), text.begin(), text.end());
        data_.push_back(0);
        return ret;
    }

    std::string const& data() const { return data_; }
};