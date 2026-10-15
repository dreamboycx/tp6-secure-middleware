<?php
/**
 * TpSecure 安全中间件配置
 */
return [
    // SQL注入检测中间件
    'sql_inject' => [
        'enable' => true,
        'sensitive_words' => [],//过滤敏感词
    ],
    // IP黑名单中间件
    'ip_limit' => [
        'enable' => false,
        'black_ip' => [
            // '123.123.123.123'
        ]
    ],
    //api接口请求频率限制
    'api_rate_limit' => [
        'enable' => false, //是否开启
        'token_name' => 'token', //存放在header里的请求token参数名称
        'limit' => 10, // 请求次数
        'time' => 60, // 时间窗口(秒)
        'return_code_name' => 'code', // 返回的code参数名称
        'return_msg_name' => 'msg', // 返回的msg参数名称
    ],
    // API签名中间件
    'api_sign' => [
        'enable' => false,
        'secret' => '',
    ]
];