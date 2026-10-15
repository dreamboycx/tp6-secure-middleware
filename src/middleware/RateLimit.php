<?php
namespace TpSecure\middleware;

use think\facade\Cache;
use think\Request;
use think\Response;

class RateLimit
{

    // 默认限制配置
    protected array $defaultLimit = [
        'limit' => 30,     // 请求次数
        'time' => 60,      // 时间窗口(秒)
    ];
    public function handle(Request $request, \Closure $next, $config = null)
    {
        $newConf = config('tpsecure.api_rate_limit');
        // 总开关
        if (isset($newConf['enable']) && !$newConf['enable']) {
            return $next($request);
        }
        $apiTokenName = $newConf['token_name'] ?? 'token';
        $token = $request->header($apiTokenName, 'anonymous');
        $ip = $request->ip();
        $apiPath = $request->pathinfo();
        // 获取限流配置
        $limitConfig = $this->getLimitConfig($config);
        // 生成唯一键
        $key = $this->generateKey($token, $ip, $apiPath);

        // 检查是否超过限制
        if ($this->isRateLimited($key, $limitConfig)) {
            return $this->responseLimitExceeded($limitConfig);
        }

        return $next($request);
    }

    protected function getLimitConfig($config): array
    {
        // 这里可以从数据库或配置文件中获取特定appId和apiPath的限流配置
        $newConf = [];
        if(is_null($config)){
            $newConf = config('tpsecure.api_rate_limit');
        }else{
            $configArr = explode(',', $config);
            if(count($configArr) == 1){
                $newConf['limit'] = $configArr[0];
            }elseif(count($configArr) == 2){
                $newConf['limit'] = $configArr[0];
                $newConf['time'] = $configArr[1];
            }
        }
        return array_merge($this->defaultLimit,$newConf);
    }

    protected function generateKey($token, $ip, $apiPath): string
    {
        return md5("{$token}_{$ip}_{$apiPath}");
    }

    protected function isRateLimited($key, $config): bool
    {
        $cache = Cache::store('redis');
        $now = time();

        // 使用Redis的有序集合实现滑动窗口计数
        $windowStart = $now - $config['time'];

        // 移除时间窗口外的记录
        $cache->zRemRangeByScore($key, 0, $windowStart);

        // 获取当前窗口内的请求数
        $requestCount = $cache->zCard($key);

        if ($requestCount >= $config['limit']) {
            return true;
        }

        // 添加当前请求时间戳
        $cache->zAdd($key, $now, $now);

        // 设置键的过期时间
        $cache->expire($key, $config['time']);

        return false;
    }

    protected function responseLimitExceeded($config): Response
    {
        $newConf = config('tpsecure.api_rate_limit');
        $return_code_name = $newConf['return_code_name'] ?? 'code';
        $return_msg_name = $newConf['return_msg_name'] ?? 'msg';
        /* $response->header([
            'X-RateLimit-Limit' => $config['limit'],
            'X-RateLimit-Remaining' => 0,
            'X-RateLimit-Reset' => time() + $config['time'],
        ]);*/

        return Response::create([
            $return_code_name => 429,
            $return_msg_name => '请求过于频繁'
        ], 'json', 429);
    }

}