import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsDefined, IsOptional, IsString } from 'class-validator';

export class CalculateBidDto {
  @ApiProperty()
  @IsString()
  @IsDefined()
  id_bid: string;

  @ApiProperty({
    description: 'Победитель тот, кто предложил пари(true - да, false - нет)',
  })
  @IsBoolean()
  @IsOptional()
  @IsDefined()
  offeredUserWin: boolean;
}
