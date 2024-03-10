import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { compare } from 'bcrypt';
import { UsersService } from 'src/modules/users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async validateUser(email: string, pass: string): Promise<any> {
    try {
      const existUser = await this.usersService.findOne(email);

      if (!existUser) throw new UnauthorizedException('User not found');
      const validatePassword = await compare(pass, existUser.password);
      if (!validatePassword)
        throw new UnauthorizedException('Wrong email or password');

      const { password, ...result } = existUser;
      return result;
    } catch (e) {
      throw new Error(e);
    }
  }

  async login(email: string, password: string) {
    try {
      const res = await this.validateUser(email, password);
      return {
        access_token: this.jwtService.sign({ res }),
      };
    } catch (e) {
      throw new Error(e);
    }
  }
}
