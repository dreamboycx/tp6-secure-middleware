<?php
namespace TpSecure\middleware;

use think\Request;
use think\Response;

class IpLimit
{
    /**
     * 黑名单IP列表
     */
    protected array $blackIp = [];
    public function handle(Request $request, \Closure $next): Response
    {
        $config = config('tpsecure.ip_limit');
        // 总开关
        if (!$config['enable']) {
            return $next($request);
        }

        $this->blackIp = array_merge($this->blackIp, $config['black_ip']);
        $clientIp = $request->ip();
        if (in_array($clientIp, $this->blackIp)) {
            return response('访问被拒绝，IP受限', 403);
        }

        return $next($request);
    }
}