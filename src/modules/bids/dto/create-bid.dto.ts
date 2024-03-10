import { ApiProperty } from '@nestjs/swagger';
import { IsDefined, IsNumber, IsOptional, IsString } from 'class-validator';

export class CreateBidDto {
  @ApiProperty()
  @IsDefined()
  @IsString()
  id_offered_user: string;

  @ApiProperty()
  @IsDefined()
  @IsString()
  id_argued_user: string;

  @ApiProperty()
  @IsDefined()
  @IsNumber()
  sum: number;

  @ApiProperty({ default: null, required: false })
  @IsString()
  @IsOptional()
  id_winner: string | null;
}
