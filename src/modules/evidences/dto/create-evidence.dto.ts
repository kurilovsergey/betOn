import { ApiProperty } from '@nestjs/swagger';
import { IsDefined, IsString } from 'class-validator';

export class CreateEvidenceDto {
  @ApiProperty()
  @IsDefined()
  @IsString()
  id_bet: string;

  @ApiProperty()
  @IsDefined()
  @IsString()
  id_user: string;

  @ApiProperty()
  @IsDefined()
  @IsString()
  description: string;
}
