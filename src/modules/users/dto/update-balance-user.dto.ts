import { ApiProperty } from '@nestjs/swagger';
import { IsDefined, IsNumber } from 'class-validator';

export class UpdateBalanceUserDto {
  @ApiProperty()
  @IsNumber()
  @IsDefined()
  //@Min(0)
  balance: number;
}
