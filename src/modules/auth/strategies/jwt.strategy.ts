import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

interface JwtPayload {
  _id: string;
  username: string;
  email: string;
  name: string;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(private readonly configService: ConfigService) {
    const secret = configService.get('JWT_SECRET');
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: secret,
    });
    this.logger.debug(`JWT_SECRET value: ${secret}`);
  }

  async validate(payload: JwtPayload) {
    return {
      _id: payload._id,
      username: payload.username,
      email: payload.email,
      name: payload.name,
    };
  }
}
