unit Unit1;

{
Copyright © 2023 Subscuto. All Rights Reserved.

This document serves as a legal notice that the copyrights to all software, source code, and related materials 
(collectively, the "Software") are owned exclusively by Subscuto. Unauthorized reproduction, distribution, 
modification, or use of the Software in any form is strictly prohibited without the express written consent of 
Subscuto.

Subscuto does not make any warranties, express or implied, with respect to the functionality, performance, or 
fitness of the Software for any particular purpose. In no event shall Subscuto be held liable for any direct, 
indirect, incidental, consequential, or any other damages arising out of or in connection with the use or inability 
to use the Software.

By using the Software, you acknowledge and agree that the Software is provided "as is" with all faults. Your use 
of the Software is entirely at your own risk. Subscuto makes no representation that the Software will meet your 
requirements, that the operation of the Software will be uninterrupted or error-free, or that defects in the Software 
will be corrected.

If you choose to use the Software, you do so at your own risk and are solely responsible for ensuring that it 
functions as intended. You are also responsible for complying with all applicable laws, regulations, and third-party 
terms and conditions related to the use of the Software.

If you do not agree with the terms of this legal notice, you must cease using the Software immediately.

All inquiries related to the Software, including requests for written permission to use, reproduce, or distribute the 
Software, should be directed to: inquiry@subscuto.com
}

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, DCPrijndael, ExtCtrls, Vcl.ComCtrls;

type
  TForm1 = class(TForm)
    Button1: TButton;
    Memo1: TMemo;
    Image1: TImage;
    Label1: TLabel;
    ProgressBar1: TProgressBar;
    procedure Button1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

type
EFileCreationFailedException = class(Exception);
TMethod=(Method1,Method2);

const
Keys:array [0..1,0..31] of Byte=(
($C9, $E6, $1A, $24, $2A, $37, $E1, $7A, $3E, $28, $85, $87, $AB, $12, $25, $67,
$31, $35, $EB, $F7, $1C, $14, $8E, $7A, $30, $6E, $0C, $36, $5F, $05, $68, $A3),
($DF, $10, $6D, $88, $A8, $CD, $FE, $BF, $F5, $7B, $F5, $17, $44, $5B, $8F, $66,
$90, $AA, $76, $E9, $17, $9A, $B5, $34, $37, $3C, $AE, $0A, $22, $2D, $C9, $BE));

var
IsLogEnabled:Boolean=True;
ZeroPad,CheckPad:array [0..262143] of Byte;
CryptedFile:TFileStream;
Cipher:TDCP_rijndael;
Key:array [0..31] of Byte;
LogFile:TextFile;

procedure LogOrShowError(ErrorMsg:string);
begin
  if IsLogEnabled then
  begin
    WriteLn(LogFile,ErrorMsg);
    WriteLn(LogFile,'');
  end
  else
    MessageBox(form1.Handle,PChar(ExtractFileName(ErrorMsg)),'Error',MB_ICONERROR);
end;

procedure ProbeKey(var Input:AnsiString; IV:PByteArray; Method:TMethod);
var
j,index:Byte;
compareto:LongWord;
temp:AnsiString;
begin
  case Method of
    Method1: compareto:=$AF77BC0F;
    Method2: compareto:=$F0A75E12;
  end;

  for j:=0 to Length(Keys) - 1 do
  begin
    temp:=Input;
    Move(Keys[j,0],Key[0],32);
    Cipher.Init(Key,Sizeof(Key)*8,IV);
    Cipher.DecryptCBC(Input[1],Input[1],Length(Input));

    if (PLongWord(@Input[9])^ <> compareto) then
    begin
      if j = 0 then
        Input:=temp
      else
        raise Exception.Create('');
    end
    else
      break;
  end;
end;

procedure Decryption_Method1(FooterSize:LongWord);
var
j:Byte;
IV:array [0..15] of Byte;
PaddingOffsets:array [0..2] of Int64;
Diff:Int64;
Input:AnsiString;
temp,decodedfilename:string;
DecodedFile:TFileStream;
begin
  temp:=ExtractFileName(CryptedFile.FileName);
  decodedfilename:=ExtractFilePath(CryptedFile.FileName) + Copy(temp,1,Pos('.ID-',temp) - 1);

  try
    try
      DecodedFile:=TFileStream.Create(decodedfilename,fmCreate);
    except
      raise EFileCreationFailedException.Create('');
    end;

    try
      // Read the IV
      CryptedFile.Position:=CryptedFile.Size - $B2 + $14;
      CryptedFile.ReadBuffer(IV[0],16);

      SetLength(Input,$C0040);
      CryptedFile.Position:=CryptedFile.Size - FooterSize;
      CryptedFile.ReadBuffer(Input[1],Length(Input));

      ProbeKey(Input,@IV[0],Method1);

      PaddingOffsets[0]:=0;
      PaddingOffsets[1]:=PInt64(@Input[$29])^;
      PaddingOffsets[2]:=PInt64(@Input[$31])^;

      CryptedFile.Position:=0;

      for j:=0 to 2 do
      begin
        CryptedFile.ReadBuffer(CheckPad[0],Length(CheckPad));
        Diff:=PaddingOffsets[j];

        if CompareMem(@CheckPad[0],@ZeroPad[0],$40000) then
        begin
          DecodedFile.WriteBuffer(Input[(j * $40000) + $39],$40000);
          Diff:=Diff + $40000;
        end
        else
          CryptedFile.Position:=CryptedFile.Position - $40000;

        if j <> 2 then
          DecodedFile.CopyFrom(CryptedFile,PaddingOffsets[j + 1] - Diff)
        else
        begin
          if CryptedFile.Size - Diff - FooterSize > 0 then
            DecodedFile.CopyFrom(CryptedFile,CryptedFile.Size - Diff - FooterSize);
        end;
      end;
    finally
      DecodedFile.Free;
    end;
  except
    on E:EFileCreationFailedException do
      LogOrShowError('Failed to create: ' + decodedfilename);
    else
      LogOrShowError('An error occured in Decryption Method 1' + #13#10 + Cryptedfile.FileName);
  end;
end;

procedure Decryption_Method2(FooterSize:LongWord);
var
IV:array [0..15] of Byte;
LoopExit:Boolean;
PaddingLength:Byte;
InputSize,i:LongWord;
Footer,Input:AnsiString;
temp,decodedfilename:string;
DecodedFile:TFileStream;
begin
  try
    // Read Footer data which holds the original filename and decrypt it
    SetLength(Footer,FooterSize - $B2);
    CryptedFile.Position:=CryptedFile.Size - FooterSize;
    CryptedFile.ReadBuffer(Footer[1],Length(Footer));

    // Read the IV
    CryptedFile.Position:=CryptedFile.Position + $14;
    CryptedFile.ReadBuffer(IV[0],16);

    ProbeKey(Footer,@IV[0],Method2);

    temp:=ExtractFileName(CryptedFile.FileName);
    decodedfilename:=ExtractFilePath(CryptedFile.FileName) + Copy(temp,1,Pos('.ID-',temp) - 1);

    // Check if the file is padded
    CryptedFile.ReadBuffer(PaddingLength,1);

    CryptedFile.Position:=0;

    try
      DecodedFile:=TFileStream.Create(decodedfilename,fmCreate);
    except
      raise EFileCreationFailedException.Create('');
    end;

    try
      i:=1;
      LoopExit:=false;
      SetLength(Input,$100000);

     Cipher.Init(Key,Sizeof(Key)*8,@IV[0]);

      repeat
        InputSize:=CryptedFile.Read(Input[1],Length(Input));
        Cipher.DecryptCBC(Input[1],Input[1],InputSize);

        if InputSize < $100000 then
          SetLength(Input,InputSize - FooterSize - PaddingLength);

        // If the input file's Rijndael encrypted part is divisible by $100000
        if (CryptedFile.Size - FooterSize) mod $100000 = 0 then
          if i = (CryptedFile.Size - FooterSize) div $100000 then
          begin
            SetLength(Input,InputSize - FooterSize - PaddingLength);
            LoopExit:=true;
          end;

        DecodedFile.WriteBuffer(Input[1],Length(Input));
        Inc(i)
      until (InputSize < $100000) or LoopExit;
    finally
      DecodedFile.Free;
    end;
  except
    on E:EFileCreationFailedException do
      LogOrShowError('Failed to create: ' + decodedfilename);
    else
      LogOrShowError('An error occured in Decryption Method 2' + #13#10 + Cryptedfile.FileName);
  end;
end;

procedure SearchPhobosFiles(const dirName:string);
var
searchResult:TSearchRec;
begin
  if FindFirst(dirName + '\*',faAnyFile,searchResult) = 0 then
  begin
    try
      repeat
        if (searchResult.Attr and faDirectory) = 0 then
        begin
          if SameText(ExtractFileExt(searchResult.Name),'.phobos') then
            Form1.Memo1.Lines.Add(IncludeTrailingBackSlash(dirName) + searchResult.Name);
        end
        else
          if (searchResult.Name <> '.') and (searchResult.Name <> '..') then
            SearchPhobosFiles(IncludeTrailingBackSlash(dirName) + searchResult.Name);
      until FindNext(searchResult) <> 0;
    finally
      FindClose(searchResult);
    end;
  end;
end;

procedure TForm1.Button1Click(Sender: TObject);
var
i:LongWord;
FooterSize:LongWord;
begin
  memo1.Clear;
  progressbar1.Position:=0;

  SearchPhobosFiles(ExtractFilePath(Application.ExeName));

  if memo1.Text = '' then
    raise Exception.Create('No .phobos files were found!')
  else
    progressbar1.Max:=Memo1.Lines.Count - 1;

  if IsLogEnabled then
  try
    AssignFile(LogFile,'log.txt');
    ReWrite(LogFile);
    WriteLn(LogFile,'Decryption process started at: ' + DateTimeToStr(Now));
    WriteLn(LogFile,'');
  except
    raise Exception.Create('An error occured while creating the log file!');
  end;

  try
    Cipher:=TDCP_rijndael.Create(nil);
  except
    raise Exception.Create('Failed to initialize the cipher!');
  end;

  try
    for i:=0 to Memo1.Lines.Count - 1 do
    try
      try
        CryptedFile:=TFileStream.Create(memo1.Lines[i],fmOpenRead);
      except
        raise EFileCreationFailedException.Create('');
      end;

      progressbar1.Position:=i;

      if Memo1.Lines.Count - 1 < 1000 then
      begin
        Application.ProcessMessages;
      end
      else
        if i mod 1000 = 0 then
          Application.ProcessMessages;

      try
        if CryptedFile.Size > 0 then
        begin
          // Read Footer size
          CryptedFile.Position:=CryptedFile.Size - 10;
          CryptedFile.ReadBuffer(FooterSize,4);

          if FooterSize > $C0000 then
            Decryption_Method1(FooterSize)
          else
            Decryption_Method2(FooterSize);
        end;
      finally
        CryptedFile.Free;
      end;
    except
      on EFileCreationFailedException do
        LogOrShowError('Failed to open: ' + memo1.Lines[i]);
    end;

    if IsLogEnabled then
    begin
      WriteLn(LogFile,'Decryption process finished at: ' + DateTimeToStr(Now));
      CloseFile(LogFile);
    end;
  finally
    Cipher.Free;
  end;

  Application.ProcessMessages;
  MessageBox(form1.Handle,'The process has finished!','Information',MB_ICONINFORMATION);
end;

procedure TForm1.FormCreate(Sender: TObject);
begin
  ZeroMemory(@ZeroPad[0],Length(ZeroPad));
end;

end.
