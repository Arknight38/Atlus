#pragma once
#include <string>
#include <variant>
#include <optional>
#include <functional>

namespace atlus {

// Error codes for different failure modes
enum class ErrorCode : uint32_t {
    // General errors
    Success = 0,
    Unknown = 1,
    NotImplemented = 2,
    InvalidArgument = 3,
    OutOfMemory = 4,
    NotFound = 5,
    
    // I/O errors
    FileNotFound = 100,
    FileAccessDenied = 101,
    FileCorrupted = 102,
    FileTooLarge = 103,
    
    // Parsing errors
    InvalidFormat = 200,
    UnsupportedFormat = 201,
    ParseError = 202,
    
    // Analysis errors
    AnalysisFailed = 300,
    DisassemblyError = 301,
    InvalidAddress = 302,
    InvalidSection = 303,
    
    // Pipeline errors
    StageFailed = 400,
    DependencyNotSatisfied = 401,
    CircularDependency = 402,
    
    // Runtime errors
    NotInitialized = 500,
    AlreadyInitialized = 501,
    InvalidState = 502,
};

// Error context with message and code
struct Error {
    ErrorCode code = ErrorCode::Unknown;
    std::string message;
    std::string file;
    int line = 0;
    
    Error() = default;
    Error(ErrorCode c, std::string m) : code(c), message(std::move(m)) {}
    Error(ErrorCode c, std::string m, std::string f, int l) 
        : code(c), message(std::move(m)), file(std::move(f)), line(l) {}
    
    bool is_error() const { return code != ErrorCode::Success; }
    explicit operator bool() const { return is_error(); }
    
    std::string to_string() const {
        return message;
    }
};

// Result type - either a value or an error
// Using std::variant for value + error storage
template<typename T>
struct Result {
private:
    std::variant<T, Error> data_;
    
public:
    Result(const T& value) : data_(value) {}
    Result(T&& value) : data_(std::move(value)) {}
    Result(const Error& error) : data_(error) {}
    Result(Error&& error) : data_(std::move(error)) {}
    
    bool is_ok() const { return std::holds_alternative<T>(data_); }
    bool is_err() const { return std::holds_alternative<Error>(data_); }
    explicit operator bool() const { return is_ok(); }
    
    const T& value() const { return std::get<T>(data_); }
    T& value() { return std::get<T>(data_); }
    const T* operator->() const { return &std::get<T>(data_); }
    T* operator->() { return &std::get<T>(data_); }
    const T& operator*() const { return std::get<T>(data_); }
    T& operator*() { return std::get<T>(data_); }
    
    const Error& error() const { return std::get<Error>(data_); }
    Error& error() { return std::get<Error>(data_); }
    
    // Get value or default
    T value_or(const T& default_val) const {
        return is_ok() ? value() : default_val;
    }
    
    // Map the value
    template<typename F>
    auto map(F&& f) -> Result<decltype(f(std::declval<T>()))> {
        using U = decltype(f(std::declval<T>()));
        if (is_ok()) {
            return Result<U>(f(value()));
        }
        return Result<U>(error());
    }
    
    // Map the error
    template<typename F>
    Result map_err(F&& f) {
        if (is_err()) {
            return Result(f(error()));
        }
        return *this;
    }
};

// Void specialization for operations with no return value
template<>
struct Result<void> {
private:
    std::optional<Error> error_;
    
public:
    Result() = default;
    Result(const Error& error) : error_(error) {}
    Result(Error&& error) : error_(std::move(error)) {}
    
    bool is_ok() const { return !error_.has_value(); }
    bool is_err() const { return error_.has_value(); }
    explicit operator bool() const { return is_ok(); }
    
    const Error& error() const { return error_.value(); }
    Error& error() { return error_.value(); }
};

// Helper macros for error creation
#define ATLUS_ERROR(code, msg) atlus::Error(code, msg, __FILE__, __LINE__)
#define ATLUS_MAKE_ERROR(code, msg) atlus::Error(code, msg)

// Helper to return early on error
#define ATLUS_TRY(result) \
    do { \
        auto&& _r = (result); \
        if (_r.is_err()) return _r.error(); \
    } while(0)

#define ATLUS_TRY_ASSIGN(var, result) \
    do { \
        auto&& _r = (result); \
        if (_r.is_err()) return _r.error(); \
        var = std::move(_r.value()); \
    } while(0)

} // namespace atlus
