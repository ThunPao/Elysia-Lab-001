import { Elysia } from 'elysia'
import { jwt } from '@elysiajs/jwt'
import { ip } from "elysia-ip";
const curJWT = String(process.env.JWT_SECRET);
new Elysia()
  .use(ip())
  .use(
    jwt({
      name: 'jwt',
      github: "ThunPao",
      quota: 50,
      secret: curJWT
    })
  )
  .get('/sign/:name', async ({ jwt, cookie: { auth }, params, ip }) => {
    auth.set({
      value: await jwt.sign({ name: params.name, ip: ip }),
      httpOnly: true,
      maxAge: 7 * 86400,
      path: '/profile',
    })
    return `Sign in as ${auth.value}`
  })
  .get('/profile', async ({ jwt, ip, set, cookie: { auth } }) => {
    const cred = await jwt.verify(auth.value)
    if (!cred) {
      set.status = 401
      return 'Never gonna give you up'
    }
    if (cred.ip != String(ip)) {
      return 'IP mismatch!'

    }
    if(Number(cred.quota)  < 1) return "Quota limit ecceed" 
    if(Number(cred.quota) > 0){
      cred.quota = Number(cred.quota) - 1;
    }
    auth.update({
      value: await jwt.sign(cred),
      httpOnly: true,
      maxAge: 7 * 86400,
      path: '/profile',
    })
    return `Hi ${cred.github} Your Quota Left is: ${cred.quota}`
  })
  .get("/ip", ({ ip }) => ip)
  .listen(3000)