'use strict';

const callbackPath = '/oauth/authorization_code_callback';

module.exports = options => {
  const {
    host,
    clientID,
    callbackUrl,
    clientSecret,
  } = options;
  return async function oauth20(ctx, next) {
    // 从cookie里面获取token
    const token = ctx.cookies.get('oauth20_token');
    const { path } = ctx.req;

    // 没有token并且地址不是回调地址,跳转过去获取token
    if (!token && path !== callbackPath) {
      return jumpToAuthorize(ctx, host, clientID, callbackUrl);
    }

    if (path === callbackPath) {
      return changeTokenToId(ctx, clientID, clientSecret, host, callbackUrl);
    }

    next();
  };
};

/**
 * 没有token,跳转过去拿token
 * @param ctx 上下文
 * @param host 目标host
 * @param clientID 申请到的clientID
 * @param callbackUrl 回调地址
 */
function jumpToAuthorize(ctx, host, clientID, callbackUrl) {
  const { returnUrl } = ctx.query;

  let path = `http://${host}/oauth/authorize`;
  path += '?response_type=code';
  path += '&scope=read';
  path += `&client_id=${clientID}`;
  path += '&state=UUID';
  path += `&redirect_uri=${encodeURIComponent(callbackUrl + callbackPath)}`;
  path += `&return_uri=${encodeURIComponent(returnUrl)}`;

  ctx.redirect(path);
}

/**
 * token 换userInfo 并写入cookie
 * @param ctx 请求上下文
 * @param clientID 申请到的clientID
 * @param clientSecret key
 * @param host 目标host
 * @param callbackUrl 回调地址
 * @returns {Promise<void>}
 */
async function changeTokenToId(ctx, clientID, clientSecret, host, callbackUrl) {
  const { query, headers } = ctx;
  const { code, returnUri } = query;

  headers.host = host;
  headers['Content-type'] = 'application/x-www-form-urlencoded;charset=UTF-8';

  const newQuery = {
    code,
    client_id: clientID,
    client_secret: clientSecret,
    grant_type: 'authorization_code',
    redirect_uri: encodeURIComponent(callbackUrl + callbackPath),
  };

  const path = Object.keys(newQuery).map(key => `${key}=${newQuery[key]}`).join('&');

  const accessResult = await ctx.curl(`http://${host}/oauth/token?${path}`, {
    headers,
    method: 'POST',
  });

  let accessTokenJson = accessResult.data.toString();

  try {
    accessTokenJson = JSON.parse(accessTokenJson);
  } catch (e) {
    ctx.body = '解析token失败';
    return;
  }

  if (!accessTokenJson || accessTokenJson.error) {
    ctx.body = '请求异常';
    return;
  }

  const userInfo = await ctx.curl(`http://${host}/oauth/rs/getuserinfo?access_token=${accessTokenJson.access_token}`, {
    headers,
    method: 'POST',
  });

  const userInfoStr = userInfo.data.toString();

  ctx.cookies.set('oauth20_token', accessTokenJson.access_token, {
    maxAge: 1000 * 60 * 60 * 12, // 一天
    encrypt: false,
    httpOnly: false,
  });

  ctx.cookies.set('user_info', encodeURIComponent(userInfoStr), {
    maxAge: 1000 * 60 * 60 * 12, // 一天
    encrypt: false,
    httpOnly: false,
  });

  ctx.redirect(returnUri);
}
