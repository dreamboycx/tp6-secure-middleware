<?php
namespace TpSecure\middleware;

use think\facade\Log;
use think\Request;
use think\Response;
class SqlInject{

    /**
     * SQL注入关键字黑名单
     * @var array
     */
    private array $sqlKeywords = [
        'select', 'union', 'insert', 'update', 'delete', 'drop', 'create',
        'alter', 'exec', 'execute', 'script', 'sleep', 'benchmark', 'waitfor',
        'declare', 'cast', 'convert', 'concat', 'char', 'nchar',
        'xp_', 'sp_', 'information_schema', 'sysobjects', 'syscolumns'
    ];

    /**
     * SQL注入特征模式
     * @var array
     */
    private array $sqlPatterns = [
        "/(\s|^)(or|and)(\s+)[\w\d]+(\s*)=(\s*)[\w\d]+/i",  // or 1=1, and 1=1
        "/(\s|^)(or|and)(\s+)'[^']*'(\s*)=(\s*)'[^']*'/i",   // or 'a'='a'
        "/union(\s+)select/i",                                // union select
        "/(\s|^)select(\s+).+(\s+)from/i",                   // select ... from
        "/'(\s*)(or|and)(\s*)'/i",                           // ' or '
        "/--/",                                               // SQL注释 --
        "/#/",                                                // SQL注释 #
        "/\/\*/",                                             // SQL注释 /*
        "/;(\s*)(drop|delete|update|insert)/i",              // ; drop
        "/exec(\s*)\(/i",                                     // exec(
        "/script/i",                                          // script标签
    ];

    /**
     * 白名单路由（不进行SQL注入检测的路由）
     * @var array
     */
    private array $whitelistRoutes = [
        // 可以添加需要排除检测的路由，例如：
        // '/admin/editor/upload',  // 富文本编辑器上传
    ];


    public function handle(Request $request, \Closure $next): Response
    {
        $config = config('tpsecure.sql_inject');
        // 总开关
        if (!$config['enable']) {
            return $next($request);
        }
        //合并敏感词
        $this->sqlKeywords = array_merge($this->sqlKeywords, $config['sensitive_words']);

        $currentRoute = $request->baseUrl();
        // 检查是否在白名单中
        if ($this->isWhitelistRoute($currentRoute)) {
            return $next($request);
        }
        // 获取所有请求参数
        $allParams = array_merge(
            $request->get(),
            $request->post(),
            $request->param()
        );

        // 检测参数中是否存在SQL注入
        foreach ($allParams as $key => $value) {
            if ($this->detectSqlInjection($key, $value)) {
                // 记录日志
                $this->logSqlInjectionAttempt($key, $value, $currentRoute);

                // 返回错误响应
                return $this->blockRequest($request,"检测到非法请求参数，请求已被拦截！");
            }
        }

        return $next($request);
    }

    /**
     * 检测SQL注入
     * @param string $key 参数名
     * @param mixed $value 参数值
     * @return bool true表示检测到注入，false表示安全
     */
    private function detectSqlInjection(string $key, $value): bool
    {
        // 跳过非字符串类型
        if (!is_string($value)) {
            return false;
        }

        // 空值跳过
        if (empty($value)) {
            return false;
        }

        $valueLower = strtolower($value);

        // 1. 检测SQL关键字
        foreach ($this->sqlKeywords as $keyword) {
            if (stripos($valueLower, $keyword) !== false) {
                // 检测到关键字后，进一步判断是否真的是SQL注入
                if ($this->isSuspiciousContext($value, $keyword)) {
                    return true;
                }
            }
        }

        // 2. 使用正则表达式检测SQL注入模式
        foreach ($this->sqlPatterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }

        // 3. 检测特殊字符组合
        if ($this->detectSpecialCharCombination($value)) {
            return true;
        }

        return false;
    }

    /**
     * 检测关键字是否处于可疑上下文中
     * @param string $value 参数值
     * @param string $keyword 检测到的关键字
     * @return bool
     */
    private function isSuspiciousContext(string $value, string $keyword): bool
    {
        // 检测关键字周围是否有SQL注入特征
        $suspiciousChars = ["'", '"', '=', '<', '>', '--', '#', ';', '/*', '*/'];

        foreach ($suspiciousChars as $char) {
            if (stripos($value, $char) !== false) {
                return true;
            }
        }

        // 检测 or/and 后面跟着等式
        if (in_array($keyword, ['or', 'and'])) {
            if (preg_match("/(or|and)\s+[\w\d]+\s*=\s*[\w\d]+/i", $value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 检测特殊字符组合
     * @param string $value 参数值
     * @return bool
     */
    private function detectSpecialCharCombination(string $value): bool
    {
        // 检测引号和等号的组合: ' = '
        if (preg_match("/'(\s*)=(\s*)'/", $value)) {
            return true;
        }

        // 检测引号和注释符号
        if (preg_match("/'(\s*)(--|#|\/\*)/", $value)) {
            return true;
        }

        // 检测分号后跟SQL语句
        if (preg_match("/;(\s*)(select|insert|update|delete|drop)/i", $value)) {
            return true;
        }

        return false;
    }


    /**
     * 检查是否为白名单路由
     * @param string $route 当前路由
     * @return bool
     */
    private function isWhitelistRoute(string $route): bool
    {
        foreach ($this->whitelistRoutes as $whiteRoute) {
            if (stripos($route, $whiteRoute) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * 记录SQL注入尝试日志
     * @param string $key 参数名
     * @param mixed $value 参数值
     * @param string $route 路由
     */
    private function logSqlInjectionAttempt(string $key, $value, string $route)
    {
        $logData = [
            'time' => date('Y-m-d H:i:s'),
            'ip' => lc_get_ip(),
            'route' => $route,
            'param_key' => $key,
            'param_value' => $value,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        ];

        // 写入日志
        Log::record(json_encode($logData));
    }

    /**
     * 阻止请求并返回错误响应
     * @param string $message 错误消息
     * @return Response
     */
    private function blockRequest($request,string $message,$code=403): Response
    {

        if ($request->isAjax()) {
            // AJAX请求返回JSON
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'code' => $code,
                'msg' => $message,
                'data' => null
            ]);
        } else {
            // 普通请求返回HTML
            header('HTTP/1.1 403 Forbidden');
            echo '<html><head><meta charset="utf-8"><title>403 Forbidden</title></head><body>';
            echo '<h1>403 Forbidden</h1>';
            echo '<p>' . htmlspecialchars($message) . '</p>';
            echo '</body></html>';
        }
        exit;
    }

}