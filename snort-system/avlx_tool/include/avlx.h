#pragma once

#ifdef __cplusplus
extern "C" {
#include <cstdint>
#else
#include <stdint.h>
#endif

/**
 * @brief 反馈编译过程中的错误
 * @details 编译过程中会遇到无法解析的规则或无法支持的规则，
 * 此时可以通过此结构了解相关的信息
 *
 */
typedef struct tagAVLXCompilerError {
  const char *message; //!< 详细描述错误原因的一段文字
  uint64_t line_no;    //!< 错误原因行号
  uint64_t index;      //!< 错误起始于第几个字符
} AVLXCompilerError, *PAVLXCompilerError;

/**
 * 引擎句柄
 */
typedef void *AVLXEngineHandle;

//! 无效句柄
#define AVLX_INVALID_HANDLE NULL
//! 成功
#define AVLX_SUCCESS 0
//! 编译失败
#define AVLX_COMPILE_FAILED 1

/**
 * @brief 初始化引擎
 * @details 初始化引擎，以供后续调用
 * @return 非 AVLX_INVALID_HANDLE 则是有效的句柄
 */
AVLXEngineHandle avlx_core_init();

/**
 * @brief 释放引擎句柄
 * @details 不再使用后释放引擎句柄
 *
 * @param handle @ref avlx_core_init 返回的句柄
 */
void avlx_core_free(AVLXEngineHandle handle);

/**
 * @brief 编译文件
 * @details 将规则文件编译为引擎库，并替换正在使用的引擎库。
 *
 * @param h 引擎句柄
 * @param f 文件路径
 * @param c_err 编译错误内容
 * @retval AVLX_SUCCESS 表示成功
 * @retval AVLX_COMPILE_FAILED 编译失败，可以通过 c_err 获取更详细的错误内容
 */
uint64_t avlx_compile_file(AVLXEngineHandle h, const char *f,
                           PAVLXCompilerError c_err);

/**
 * @brief IP 头
 * @details 主要用于 IP 地址匹配。
 *
 * 当使用 IPv4 时，192.168.100.195 表示为 | C0 A8
 * 64 C3 | 固定长度为 4 字节。
 *
 * 当 `flags | AVLX_FLOW_FLAGS_TO_SERVER` 为真
 *  - src 是客户端 ip
 *  - dst 是服务器 ip
 *
 * 当 `flags | AVLX_FLOW_FLAGS_TO_CLIENT` 为真
 *  - src 是服务器 ip
 *  - dst 是客户端 ip
 *
 */
typedef struct tagIP {
  const char *src; //!< 指向源IP
  const char *dst; //!< 指向目的IP
  /** 当前 payload 标志位
   * 取值范围
   *  - @ref AVLX_FLOW_FLAGS_TO_CLIENT
   *  - @ref AVLX_FLOW_FLAGS_FROM_SERVER
   *  - @ref AVLX_FLOW_FLAGS_TO_SERVER
   *  - @ref AVLX_FLOW_FLAGS_FROM_CLIENT
   */
  uint64_t flags;
} IPMeta, *PIPMeta;

//! 当前 payload 是从 ** 服务器端发出 ** 的数据
#define AVLX_FLOW_FLAGS_TO_CLIENT (1 << 0)
//! 当前 payload 是从 ** 服务器端发出 ** 的数据
#define AVLX_FLOW_FLAGS_FROM_SERVER (1 << 0)
//! 当前 payload 是从 ** 从客户端发出 ** 的数据
#define AVLX_FLOW_FLAGS_TO_SERVER (1 << 1)
//! 当前 payload 是从 ** 从客户端发出 ** 的数据
#define AVLX_FLOW_FLAGS_FROM_CLIENT (1 << 1)

/**
 * @brief 数据包 元数据
 * @details 主要用于 匹配
 *
 */
typedef struct tagPacket {
  IPMeta ip;           //!< IP 元数据
  union {
    struct {
      const char *src;     //!< 源端口
      const char *dst;     //!< 目的端口
    };
    struct {
      uint8_t itype;
      uint8_t icode;
      uint16_t id;
      uint8_t reserved[12];
    }icmp;
  };
  const char *payload; //!< payload 数据
  unsigned int len;    //!< payload 数据长度
} PktMeta, *PPktMeta;

typedef struct tagAVLXFile {
  const char *payload; //!< payload 数据
  unsigned int len;    //!< payload 数据长度
} FileMeta, *PFileMeta;

/**
 * @brief TCP 元数据
 * @details 主要用于 TCP 匹配
 *
 */
typedef struct tagPacket TCPMeta, *PTCPMeta;

/**
 * @brief 匹配 TCP
 * @details 使用 TCP 规则集合进行匹配
 *
 * @param h 引擎句柄
 * @param tcp TCP 元数据
 * @return 检测到的规则号
 * @retval 0 未命中任何已知规则
 */
uint64_t avlx_match_tcp(AVLXEngineHandle h, PTCPMeta tcp);

/**
 * @brief 匹配 TCP
 * @details 使用 TCP 规则集合进行匹配
 *
 * @param h 引擎句柄
 * @param tcp TCP 元数据
 * @param f 文件元数据
 * @return 检测到的规则号
 * @retval 0 未命中任何已知规则
 */
uint64_t avlx_match_tcp_file(AVLXEngineHandle h, PTCPMeta tcp, PFileMeta f);


/**
 * @brief UDP 元数据
 * @details 主要用于 UDP 匹配
 *
 */
typedef struct tagPacket UDPMeta, *PUDPMeta;

/**
 * @brief 匹配 UDP
 * @details 使用 UDP 规则集合进行匹配
 *
 * @param h 引擎句柄
 * @param udp UDP 元数据
 * @return 检测到的规则号
 * @retval 0 未命中任何已知规则
 */
uint64_t avlx_match_udp(AVLXEngineHandle h, PTCPMeta udp);

/**
 * @brief HTTP 元数据
 * @details 主要用于 HTTP 匹配
 *
 */
typedef struct tagHTTP {
  TCPMeta tcp;                  //!< tcp 元数据
  const char *uri;              //!< uri
  unsigned int uri_len;         //!< uri 长度
  const char *header;           //!< header
  unsigned int header_len;      //!< header 长度
  const char *client_body;      //!< 请求的 body
  unsigned int client_body_len; //!< 请求 body 的长度
  const char *method;           //!< 请求方法
  unsigned int method_len;      //!< 请求方法的长度
  const char *cookie;           //!< cookie
  unsigned int cookie_len;      //!< cookie 的长度
  const char *stat_msg;         //!< 返回的状态描述
  unsigned int stat_msg_len;    //!< 状态描述的长度
  const char *stat_code;        //!< 返回的状态码
  unsigned int stat_code_len;   //!< 状态码长度
} HTTPMeta, *PHTTPMeta;

/**
 * @brief 匹配 HTTP 
 * @details 使用 HTTP 规则集合进行匹配
 * 
 * @param h 引擎句柄
 * @param http HTTP 元数据
 * @return 检测到的规则号
 * @retval 0 未命中任何已知规则
 */
uint64_t avlx_match_http(AVLXEngineHandle h, PHTTPMeta http);

/**
 * @brief 匹配 HTTP 
 * @details 使用 HTTP 规则集合进行匹配
 * 
 * @param h 引擎句柄
 * @param http HTTP 元数据
 * @param f 文件元数据
 * @return 检测到的规则号
 * @retval 0 未命中任何已知规则
 */
uint64_t avlx_match_http_file(AVLXEngineHandle h, PHTTPMeta http, PFileMeta f);

/**
 * @brief DNS 元数据
 * @details 主要用于 DNS 匹配
 *
 */
typedef struct tagDNS {
  TCPMeta udp;                  //!< udp 元数据
  const char *domain;           //!< 域名
  unsigned int domain_len;      //!< 域名长度
}DNSMeta,*PDNSMeta;

/**
 * @brief 匹配 DNS 
 * @details 使用 DNS 规则集合进行匹配
 * 
 * @param h 引擎句柄
 * @param dns DNS 元数据
 * @return 检测到的规则号
 * @retval 0 未命中任何已知规则
 */
uint64_t avlx_match_dns(AVLXEngineHandle h, PDNSMeta dns);

/**
 * @brief 匹配 ICMP
 * @details 使用 ICMP 规则集合进行匹配，主要针对隐蔽信道
 * 
 * @param h 引擎句柄
 * @param icmp 引擎数据
 * 
 * @return 检测到的规则号
 * @retval 0 未命中任何已知规则
 */
uint64_t avlx_match_icmp(AVLXEngineHandle h, PPktMeta icmp);

/**
 * @brief 根据 rid 获取 sid 信息
 * @details 在 snort/suricata 规则里面 sid 是非常重要的。
 * 
 * @param h 引擎句柄
 * @param rid 命中的规则编号
 * @return 文字描述
 */
const char* avlx_get_sid(AVLXEngineHandle h, uint64_t rid);

/**
 * @brief 根据 rid 获取 msg 信息
 * @details 获取对应 snort/suricata 规则里面的 msg 。
 * 
 * @param h 引擎句柄
 * @param rid 命中的规则编号
 * @return 文字描述
 */
const char* avlx_get_msg(AVLXEngineHandle h, uint64_t rid);

/**
 * @brief 根据 rid 获取 识别出的协议信息
 * @details 仅针对规则中有 dpi 字段的有效。
 * 
 * @param h 引擎句柄
 * @param rid 规则编号
 * 
 * @retval 0xFFFFFFFF 未命中
 */
const uint32_t avlx_get_proto(AVLXEngineHandle h, uint64_t rid);

/**
 * @brief 根据 rid 获取 规则优先级
 * @details 仅针对规则中有 priority 字段的有效。
 * 
 * @param h 引擎句柄
 * @param rid 规则编号
 * 
 * @return 返回值为 0xFFFF-priority
 * @retval 0xFFFF 默认
 */
const uint16_t avlx_get_priority(AVLXEngineHandle h, uint64_t rid);

/**
 * @brief 根据 rid 获取 规则对应的动作
 * @details 仅针对规则中有 priority 字段的有效。
 * 
 * @param h 引擎句柄
 * @param rid 规则编号
 * 
 * @return 返回值为 0xFFFF-priority
 * @retval 0 NONE
 * @retval 1 PASS
 * @retval 2 DROP
 * @retval 3 REJECT
 * @retval 4 ALERT
 */
const uint8_t avlx_get_act(AVLXEngineHandle h, uint64_t rid);

#ifdef __cplusplus
}
#endif