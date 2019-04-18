{-# language BangPatterns #-}
{-# language DeriveAnyClass #-}
{-# language OverloadedStrings #-}
{-# language LambdaCase #-}
{-# language DerivingStrategies #-}
{-# language DeriveGeneric #-}

module Main where

import Control.Applicative ((<|>))
import Control.Applicative (liftA2)
import Control.Exception (bracket)
import Data.Aeson ((.:),(.:?),(.!=))
import Data.Aeson (FromJSON)
import Data.Bifunctor (first,second,bimap)
import Data.ByteString (ByteString)
import Data.HashMap.Strict (HashMap)
import Data.Int (Int64)
import Data.IntMap (IntMap)
import Data.Map.Strict (Map)
import Data.String (fromString)
import Data.Text (Text)
import Language.Asn.Types (ObjectIdentifier(..))
import Net.Types (IPv4(..))
import Snmp.Types (BindingResult(..),VarBind(..))
import Snmp.Types (MessageV2(..),Pdus(..),TrapPdu(..),ObjectSyntax(..))
import Snmp.Types (SimpleSyntax(..),ApplicationSyntax(..),GenericTrap(..))
import System.Log.FastLogger (LoggerSet)

import qualified Chronos as C
import qualified Data.Aeson as AE
import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as BC
import qualified Data.HashMap.Strict as HM
import qualified Data.IntMap.Strict as IM
import qualified Data.List as L
import qualified Data.Map.Strict as M
import qualified Data.Primitive as PM
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Language.Asn.Decoding as AsnDecoding
import qualified Net.IPv4 as IPv4
import qualified Network.Socket as NS
import qualified Network.Socket.ByteString as NSB
import qualified Snmp.Decoding as SnmpDecoding
import qualified System.Log.FastLogger as FL

main :: IO ()
main = do
  AE.eitherDecodeFileStrict "settings.json" >>= \case
    Left e -> fail ("bad settings file: " ++ e)
    Right s -> bracket
      (liftA2 (,) (outputToLoggerSet (settingsLogging s)) (outputToLoggerSet (settingsNagios s)))
      (\(output,nagios) -> FL.rmLoggerSet output *> FL.rmLoggerSet nagios)
      (\(output,nagios) -> runUDPServerForever output nagios s)

outputToLoggerSet :: Output -> IO LoggerSet
outputToLoggerSet = \case
  OutputStdout -> FL.newStdoutLoggerSet 4096
  OutputStderr -> FL.newStderrLoggerSet 4096
  OutputFile path -> FL.newFileLoggerSet 4096 path

runUDPServerForever ::
     LoggerSet -- ^ this logger should write to stdout or a log file
  -> LoggerSet -- ^ this logger should write to a nagios named pipe
  -> Settings
  -> IO ()
runUDPServerForever output nagios (Settings resolver services hosts notes _ _) = do
  FL.pushLogStr output "Beginning trapper."
  -- FL.pushLogStr output (FL.toLogStr (BB.toLazyByteString ("Beginning trapper. Decoding OIDs with:" <> encodeResolver resolver)))
  sock <- NS.socket NS.AF_INET NS.Datagram NS.defaultProtocol
  NS.bind sock (NS.SockAddrInet 162 0)
  FL.pushLogStr output "\nBound to port 162. Listening for SNMP traps.\n"
  let go = do
        (bs,sockAddr) <- NSB.recvFrom sock 4096
        C.Time nanoseconds <- C.now
        let seconds = div nanoseconds 1000000000
        let addr = sockAddrToIPv4 sockAddr
        case AsnDecoding.ber SnmpDecoding.messageV2 bs of
          Left err -> do
            FL.pushLogStr output (FL.toLogStr (BB.toLazyByteString ("Failed to decode trap from " <> IPv4.builderUtf8 addr <> " with error: " <> fromString err)))
          Right (MessageV2 _ (PdusSnmpTrap trap)) -> do
            FL.pushLogStr output (FL.toLogStr (BB.toLazyByteString (prettyTrapToBuilder resolver hosts addr trap)))
            FL.pushLogStr nagios (FL.toLogStr (BB.toLazyByteString (trapToBuilder resolver hosts services notes seconds addr trap)))
            -- The nagios handle is flushed after every write. We do this because
            -- other processes may be appending to this file as well. Flushing here
            -- means that only very large messages (bigger than 4K) run a risk of
            -- getting split in half by another message.
            FL.flushLogStr nagios
          _ -> FL.pushLogStr output (FL.toLogStr (BB.toLazyByteString ("Wrong PDU type in trap from " <> IPv4.builderUtf8 addr)))
        go
  go

trapToBuilder :: Resolver -> Map IPv4 ByteString -> HashMap ByteString Service -> HashMap ByteString ByteString -> Int64 -> IPv4 -> TrapPdu -> BB.Builder
trapToBuilder r hosts services notes seconds addr (TrapPdu oid _ typ code _ vars) = case HM.lookup trapName services of
  Nothing -> mempty
  Just (Service name status) ->
       BB.char7 '['
    <> BB.int64Dec seconds
    <> "] PROCESS_SERVICE_CHECK_RESULT;"
    <> maybe (IPv4.builderUtf8 addr) BB.byteString (M.lookup addr hosts)
    <> BB.char7 ';'
    <> BB.byteString name
    <> BB.char7 ';'
    <> BB.char7 (case status of {StatusOk -> '0'; StatusWarning -> '1'; StatusCritical -> '2'; StatusUnknown -> '3'})
    <> BB.char7 ';'
    <> "Variables:"
    <> foldMap (encodeVarBind "<br>" r) vars
    <> (maybe mempty (\x -> "<br>" <> BB.byteString x) (HM.lookup trapName notes))
    <> BB.char7 '\n'
  where
  trapName = trapDescription leftovers (fromIntegral code) typ
  (_,_,_,leftovers) = description oid r

prettyTrapToBuilder :: Resolver -> Map IPv4 ByteString -> IPv4 -> TrapPdu -> BB.Builder
prettyTrapToBuilder r reverseDns addr (TrapPdu oid _ typ code _ vars) =
     "\nHost Address: "
  <> IPv4.builderUtf8 addr
  <> "\nHost: "
  <> maybe (IPv4.builderUtf8 addr) BB.byteString (M.lookup addr reverseDns)
  <> "\nTrap Base: "
  <> descr
  <> "\nTrap Type: "
  <> BB.byteString (trapDescription leftovers (fromIntegral code) typ)
  <> "\nVariables:"
  <> foldMap (encodeVarBind (BC.singleton '\n') r) vars
  <> "\n"
  where
  (descr,_,_,leftovers) = description oid r

encodeVarBind :: ByteString -> Resolver -> VarBind -> BB.Builder
encodeVarBind sep r (VarBind name res) = BB.byteString sep <> descr <> ": " <> encodeResult r m res
  where
  (descr,m,_,_) = description name r

encodeResult :: Resolver -> IntMap ByteString -> BindingResult -> BB.Builder
encodeResult r m = \case
  BindingResultValue obj -> encodeObjectSyntax r m obj
  BindingResultUnspecified -> "unspecified"
  BindingResultNoSuchObject -> "no such object"
  BindingResultNoSuchInstance -> "no such instance"
  BindingResultEndOfMibView -> "end of mib view"

encodeObjectSyntax :: Resolver -> IntMap ByteString -> ObjectSyntax -> BB.Builder
encodeObjectSyntax _ m (ObjectSyntaxSimple (SimpleSyntaxInteger i)) = maybe (BB.int32Dec i) BB.byteString (IM.lookup (fromIntegral i) m)
encodeObjectSyntax _ _ (ObjectSyntaxSimple (SimpleSyntaxString b)) = BB.byteString b
encodeObjectSyntax r _ (ObjectSyntaxSimple (SimpleSyntaxObjectId oid)) = let (name,_,_,_) = description oid r in name
encodeObjectSyntax _ _ (ObjectSyntaxApplication (ApplicationSyntaxIpAddress addr)) = IPv4.builderUtf8 (IPv4 addr)
encodeObjectSyntax _ _ (ObjectSyntaxApplication (ApplicationSyntaxCounter w)) = BB.word32Dec w
encodeObjectSyntax _ _ (ObjectSyntaxApplication (ApplicationSyntaxTimeTicks w)) = BB.word32Dec w
encodeObjectSyntax _ _ (ObjectSyntaxApplication (ApplicationSyntaxArbitrary _)) = mempty
encodeObjectSyntax _ _ (ObjectSyntaxApplication (ApplicationSyntaxBigCounter w)) = BB.word64Dec w
encodeObjectSyntax _ _ (ObjectSyntaxApplication (ApplicationSyntaxUnsignedInteger w)) = BB.word32Dec w

-- This discards the numeric interpretations.
encodeResolver :: Resolver -> BB.Builder
encodeResolver (Resolver name0 _ _ numbers0) = BB.byteString name0 <> go 0 numbers0 where
  go !indent !numbers = IM.foldMapWithKey
    (\i (Resolver name _ _ numbersNext) -> BB.char7 '\n' <> (BB.byteString (BC.replicate indent ' ')) <> BB.intDec i <> ": " <> BB.byteString name <> go (indent + 1) numbersNext
    ) numbers

trapDescription :: IntMap Resolver -> Int -> GenericTrap -> ByteString
trapDescription r code = \case
  GenericTrapColdStart -> "coldStart"
  GenericTrapWarmStart -> "warmStart"
  GenericTrapLinkDown -> "linkDown"
  GenericTrapLinkUp -> "linkUp"
  GenericTrapAuthenticationFailure -> "authenticationFailure"
  GenericTrapEgpNeighborLoss -> "egpNeighborLoss"
  GenericTrapEnterpriseSpecific
    | Just (Resolver name _ _ _) <- IM.lookup 0 r >>= (IM.lookup code . resolverNumbers) -> name
    | Just (Resolver name _ _ _) <- IM.lookup code r -> name
    | otherwise -> BC.pack (show code)

sockAddrToIPv4 :: NS.SockAddr -> IPv4
sockAddrToIPv4 (NS.SockAddrInet _ addr) = IPv4.fromTupleOctets (NS.hostAddressToTuple addr)
sockAddrToIPv4 _ = IPv4.any

instance FromJSON Resolver where
  parseJSON = id
    . fmap (M.foldMapWithKey (\oid (NamedInterpretation name interpretation traps) -> describe oid name interpretation traps))
    . AE.parseJSON

data NamedInterpretation = NamedInterpretation !ByteString !(IntMap ByteString) !(IntMap ByteString)

instance FromJSON NamedInterpretation where
  parseJSON x =
    AE.withText "NamedInterpretation" (\t -> return (NamedInterpretation (TE.encodeUtf8 t) IM.empty IM.empty)) x
    <|>
    AE.withObject "NamedInterpretation"
      (\m -> NamedInterpretation
        <$> fmap TE.encodeUtf8 (m .: "name")
        <*> (fmap.fmap) TE.encodeUtf8 (fmap toIntMap (m .:? "interpretation" .!= M.empty))
        <*> (fmap.fmap) TE.encodeUtf8 (fmap toIntMap (m .:? "traps" .!= M.empty))
      ) x

toIntMap :: Map Int a -> IntMap a
toIntMap = IM.fromList . M.toList

data Settings = Settings
  { settingsDescriptions :: !Resolver
  , settingsServices :: !(HashMap ByteString Service)
  , settingsHosts :: !(Map IPv4 ByteString)
  , settingsNotes :: !(HashMap ByteString ByteString)
  , settingsNagios :: !Output
  , settingsLogging :: !Output
  }

instance FromJSON Settings where
  parseJSON = AE.withObject "Settings" $ \m -> Settings
    <$> m .: "descriptions"
    <*> fmap (HM.fromList . map (first TE.encodeUtf8) . HM.toList) (m .: "services")
    <*> fmap (M.fromList . map (second TE.encodeUtf8) . HM.toList) (m .: "hosts")
    <*> fmap (HM.fromList . map (bimap TE.encodeUtf8 TE.encodeUtf8) . HM.toList) (m .: "notes")
    <*> m .: "nagios"
    <*> m .: "logging"

data Output
  = OutputFile String
  | OutputStdout
  | OutputStderr

instance FromJSON Output where
  parseJSON = AE.withText "Service" $ \t -> pure $ case t of
    "stdout" -> OutputStdout
    "stderr" -> OutputStderr
    _ -> OutputFile (T.unpack t)

data Status = StatusOk | StatusWarning | StatusCritical | StatusUnknown
  deriving stock (Eq,Ord)

data Service = Service
  { serviceName :: !ByteString
  , serviceStatus :: !Status
  }

instance FromJSON Service where
  parseJSON = AE.withText "Service" $ \t -> case T.splitOn (T.singleton '.') t of
    [a,b] -> maybe
      (fail "invalid status, expected: ok, warning, critical, or unknown")
      (pure . Service (TE.encodeUtf8 a))
      (statusFromText b)
    _ -> fail "service should be separated by a dot"

statusFromText :: Text -> Maybe Status
statusFromText = \case
  "ok" -> Just StatusOk
  "warning" -> Just StatusWarning
  "critical" -> Just StatusCritical
  "unknown" -> Just StatusUnknown
  _ -> Nothing

data Resolver = Resolver
  { resolverName :: !ByteString
  , resolverInterpretation :: !(IntMap ByteString)
  , resolverTraps :: !(IntMap ByteString)
  , resolverNumbers :: !(IntMap Resolver)
  }

-- A resolution of a lookup performed in the resolver trie.
-- The Solved data constructor means that we have gone as
-- deep as we can in the trie.
data Resolution
  = ResolutionNaming !Resolver
  | ResolutionSolved
      !ByteString
      !(IntMap ByteString)
      ![Word] -- these words are built up backwards

instance Semigroup Resolver where
  Resolver a1 b1 c1 d1 <> Resolver a2 b2 c2 d2 = Resolver (max a1 a2) (IM.union b1 b2) (IM.union c1 c2) (IM.unionWith (<>) d1 d2)

instance Monoid Resolver where
  mempty = Resolver B.empty IM.empty IM.empty IM.empty

-- Build a resolver that resolves a single OID to a description.
describe :: ObjectIdentifier -> ByteString -> IntMap ByteString -> IntMap ByteString -> Resolver
describe (ObjectIdentifier x) name interpretation traps = PM.foldrPrimArray
  (\w r -> Resolver B.empty IM.empty IM.empty (IM.singleton (wordToInt w) r))
  (Resolver name interpretation traps IM.empty)
  x

-- Break an OID into a human-readable description and a list
-- of leftover numbers.
resolution :: ObjectIdentifier -> Resolver -> Resolution
resolution (ObjectIdentifier x) r0 =
  PM.foldlPrimArray'
    ( \b w -> case b of
      ResolutionNaming (Resolver name _ traps numbers) ->
        case IM.lookup (wordToInt w) numbers of
          Nothing -> ResolutionSolved name traps [w]
          Just r -> ResolutionNaming r { resolverTraps = IM.union (resolverTraps r) traps }
      ResolutionSolved name traps ws -> ResolutionSolved name traps (w : ws)
    ) (ResolutionNaming r0) x

-- Fetch the human-readable description of an OID from a resolver.
-- This concatenates the leftover numbers to the end. The second
-- tuple element is a map that resolves numeric descriptions (often
-- a status code) to something human-readable.
description :: ObjectIdentifier -> Resolver -> (BB.Builder,IntMap ByteString,IntMap ByteString,IntMap Resolver)
description oid r = case resolution oid r of
  ResolutionNaming (Resolver name interpretation traps rs) -> (BB.byteString name, interpretation, traps, rs)
  ResolutionSolved name traps ws -> (BB.byteString name <> L.foldl' (\bb w -> BB.char7 '.' <> BB.wordDec w <> bb) mempty ws, IM.empty, traps, IM.empty)

wordToInt :: Word -> Int
wordToInt = fromIntegral

