import bcrypt from 'bcrypt';
import {CookieOptions, Request, Response, Router} from 'express';
import StatusCodes from 'http-status-codes';

import UserDao from '@daos/User/UserDao.mock';
import { JwtService } from '@shared/JwtService';
import { paramMissingError, loginFailedErr, cookieProps, IRequest } from '@shared/constants';
import {adminMW} from "./middleware";

const router = Router();
const userDao = new UserDao();
const jwtService = new JwtService();
const { BAD_REQUEST, OK, UNAUTHORIZED } = StatusCodes;



/******************************************************************************
 *                      Login User - "POST /api/auth/login"
 ******************************************************************************/

router.post('/login', async (req: IRequest, res: Response) => {
    // Check email and password present
    const { email, password } = req.body;
    if (!(email && password)) {
        return res.status(BAD_REQUEST).json({
            error: paramMissingError,
        });
    }
    // Fetch user
    const user = await userDao.getOne(email);
    if (!user) {
        return res.status(UNAUTHORIZED).json({
            error: loginFailedErr,
        });
    }
    // Check password
    const pwdPassed = await bcrypt.compare(password, user.pwdHash);
    if (!pwdPassed) {
        return res.status(UNAUTHORIZED).json({
            error: loginFailedErr,
        });
    }
    // Setup Admin Cookie
    const jwt = await jwtService.getJwt({
        id: user.id,
        role: user.role,
    });
    const { key, options } = cookieProps;
    res.cookie(key, jwt, options as CookieOptions); 
    // Return
    return res.status(OK).end();
});



/******************************************************************************
 *                      Logout - "GET /api/auth/logout"
 ******************************************************************************/

router.get('/logout', (req: Request, res: Response) => {
    const { key, options } = cookieProps;
    res.clearCookie(key, options);
    return res.status(OK).end();
});

router.get('/auth', async (req: Request, res: Response) => {
  return await adminMW(req,res,async ()=>{
    return res.status(OK).json({loggedIn: true});})
});



/******************************************************************************
 *                                 Export Router
 ******************************************************************************/

export default router;
