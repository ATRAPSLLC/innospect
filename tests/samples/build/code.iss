; Compiled-script sample: a [Code] section exercising every construct the
; PascalScript (IFPS) lift has to model. Compiles under Inno Setup >= 6.0.
; Output: `code.exe`; land it locally as `code-tool<X_Y_Z>.exe`.
;
; Build: ISCC.exe code.iss
;
; Each routine below exists for one construct, named in its comment, so a
; test can find the procedure by name and assert what its lift must show.

[Setup]
AppName=Inno Test (code)
AppVersion=1.0.0
AppVerName=Inno Test (code) 1.0.0
AppPublisher=BinFlip
DefaultDirName={tmp}\InnoTestCode
OutputDir=.
OutputBaseFilename=code
Compression=lzma
SolidCompression=yes

[Files]
Source: "payload.txt"; DestDir: "{app}"; Flags: ignoreversion

[Code]
type
  TCell = record
    X: Integer;
    Y: Integer;
  end;
  TCounts = array[0..3] of Integer;

var
  { Globals: a scalar, a string, a record and a dynamic array. }
  GCounter: Integer;
  GName: String;
  GOrigin: TCell;
  GLog: array of String;

{ A DLL import: an external procedure with a typed declaration. }
function MessageBeep(uType: Cardinal): Boolean;
  external 'MessageBeep@user32.dll stdcall';

{ Arithmetic on parameters, a local, and a function result. }
function Scale(Value, Factor: Integer): Integer;
var
  Tmp: Integer;
begin
  Tmp := Value * Factor;
  Result := Tmp + (Value mod 7) - (Factor shl 2);
end;

{ A var parameter written through, and a global written in a callee. }
procedure Bump(var Target: Integer; Step: Integer);
begin
  Target := Target + Step;
  GCounter := GCounter + 1;
end;

{ Every comparison, both branch polarities, and a counted loop. }
function Classify(Value: Integer): Integer;
var
  I: Integer;
begin
  Result := 0;
  if Value < 0 then
    Result := -1
  else if Value > 100 then
    Result := 2
  else if (Value >= 10) and (Value <= 20) then
    Result := 1;
  for I := 0 to 3 do
    if Value <> I then
      Result := Result + 1;
end;

{ A while loop with a back edge, and a case statement. }
function Digits(Value: Integer): String;
begin
  Result := '';
  while Value > 0 do
  begin
    case Value mod 10 of
      0: Result := '0' + Result;
      1, 2, 3: Result := 'l' + Result;
    else
      Result := 'h' + Result;
    end;
    Value := Value div 10;
  end;
end;

{ Record fields, a static array, and a dynamic array. }
function Layout: Integer;
var
  P: TCell;
  Counts: TCounts;
  I: Integer;
begin
  P.X := 3;
  P.Y := GOrigin.Y + 4;
  for I := 0 to 3 do
    Counts[I] := I * P.X;
  SetArrayLength(GLog, 2);
  GLog[0] := 'x';
  GLog[1] := IntToStr(Counts[2]);
  Result := P.X + P.Y + GetArrayLength(GLog);
end;

{ try/finally and try/except, with a raise. }
function Guarded(Value: Integer): Integer;
begin
  Result := 0;
  try
    try
      if Value = 0 then
        RaiseException('zero');
      Result := 100 div Value;
    finally
      GCounter := GCounter + 1;
    end;
  except
    Result := -1;
  end;
end;

{ Strings, Boolean logic, the Inno API, and the DLL import. }
function Describe(const Prefix: String; Flag: Boolean): String;
begin
  Result := Prefix + ':' + IntToStr(Length(Prefix));
  if Flag and not (Prefix = '') then
    Result := Uppercase(Result);
  if FileExists(ExpandConstant('{app}\payload.txt')) then
    Result := Result + '!';
  MessageBeep(0);
end;

{ An event function: the entry the installer calls, calling every routine. }
function InitializeSetup: Boolean;
var
  Total: Integer;
begin
  GName := 'code';
  GOrigin.X := 1;
  GOrigin.Y := 2;
  Total := Scale(6, 7);
  Bump(Total, Classify(Total));
  Total := Total + Layout + Guarded(Total);
  Log(Describe(GName + Digits(Total), Total > 0));
  Result := True;
end;
