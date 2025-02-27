package io.joern.scanners.php

import io.joern.console.*
import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.joern.macros.QueryMacros.*
import io.joern.scanners.*
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.nodes.NewFinding

object PhpJoern extends QueryBundle {

  implicit val resolver: ICallResolver = NoResolve

  @q
  def sqli()(implicit context: EngineContext): Query =
    Query.make(
      name = "phpjoern_sqli",
      author = Crew.yichao,
      title = "CWE-89(SQL Injection): A parameter is used in an insecure sqli related func call.",
      description = """
          |An attacker controlled parameter is used in an insecure sqli related func call.
          |
          |If the parameter is not validated and sanitized, this may result in a SQL injection.
          |""".stripMargin,
      score = 5,
      withStrRep({ cpg =>
        // $_REQUEST["foo"], $_GET["foo"], $_POST["foo"]
        // are identifier (at the moment)
        def sources = cpg.assignment.source.code(".*_(REQUEST|GET|POST).*")
        def sinks = cpg.call.name("(query|mysql_query|mysqli_query|mysqli_prepare|mysqli_execute|pg_query|pg_prepare)")
                
        // Find the first matching source-sink pair
        val cartesian = sources.flatMap(i => sinks.map(j => (i, j)))
        val allMatches = cartesian.filter((src, sink) => sink.argument.reachableBy(src).hasNext)
        // Return the first matching pair's sink argument as an iterator
        allMatches.flatMap((src, sink) => List(src, sink))
      }),
      tags = List(QueryTags.sqlInjection, QueryTags.default)
    )

  @q
  def cmdi()(implicit context: EngineContext): Query =
    Query.make(
      name = "phpjoern_cmdi",
      author = Crew.yichao,
      title = "CWE-77(Command Injection): A parameter is used in an insecure cmdi related func call.",
      description = """
          |An attacker controlled parameter is used in an insecure cmdi related func call.
          |
          |If the parameter is not validated and sanitized, this is a remote code execution.
          |""".stripMargin,
      score = 5,
      withStrRep({ cpg =>
        // $_REQUEST["foo"], $_GET["foo"], $_POST["foo"]
        // are identifier (at the moment)
        def sources = cpg.assignment.source.code(".*_(REQUEST|GET|POST).*")
        def sinks = cpg.call.name("(system|exec|shell_exec|passthru|popen|proc_open|backticks)")
        // Find the first matching source-sink pair
        val cartesian = sources.flatMap(i => sinks.map(j => (i, j)))
        val allMatches = cartesian.filter((src, sink) => sink.argument.reachableBy(src).hasNext)
        // Return the first matching pair's sink argument as an iterator
        allMatches.flatMap((src, sink) => List(src, sink))
      }),
      tags = List(QueryTags.xss, QueryTags.default)
    ) 
    
  @q
  def codei()(implicit context: EngineContext): Query =
    Query.make(
      name = "phpjoern_codei",
      author = Crew.yichao,
      title = "CWE-94(Code Injection): A parameter is used in an insecure codei related func call.",
      description = """
          |An attacker controlled parameter is used in an insecure codei related func call.
          |
          |If the parameter is not validated and sanitized, this is a remote code execution.
          |""".stripMargin,
      score = 5,
      withStrRep({ cpg =>
        // Get all potential sources
        val sources = cpg.assignment.source.code(".*_(REQUEST|GET|POST).*")
        
        // Get all potential dangerous function calls
        val sinks = cpg.call.name(
          "(eval|assert|create_function|include|include_once|require|require_once|call_user_func|call_user_func_array)"
        )
        
        // Find the first matching source-sink pair
        val cartesian = sources.flatMap(i => sinks.map(j => (i, j)))
        val allMatches = cartesian.filter((src, sink) => sink.argument.reachableBy(src).hasNext)
        // Return the first matching pair's sink argument as an iterator
        allMatches.flatMap((src, sink) => List(src, sink))
      }),
      tags = List(QueryTags.remoteCodeExecution, QueryTags.default)
    ) 

  @q
  def uuf()(implicit context: EngineContext): Query =
    Query.make(
      name = "phpjoern_uuf",
      author = Crew.yichao,
      title = "CWE-434(Unrestricted Upload of File): A parameter is used in an insecure uuf related func call.",
      description = """
          |An attacker controlled parameter is used in an insecure uuf related func call.
          |
          |If the parameter is not validated and sanitized, this may result in remote code execution.
          |""".stripMargin,
      score = 5,
      withStrRep({ cpg =>
        // $_REQUEST["foo"], $_GET["foo"], $_POST["foo"]
        // are identifier (at the moment)
        def sources = cpg.assignment.source.code(".*_(REQUEST|GET|POST).*")
        def sinks = cpg.call.name("(file_get_contents|readfile|fgets|file|fopen|file_put_contents|fwrite|move_uploaded_file|unlink|rename|chmod|chown)")
 
        // Find the first matching source-sink pair
        val cartesian = sources.flatMap(i => sinks.map(j => (i, j)))
        val allMatches = cartesian.filter((src, sink) => sink.argument.reachableBy(src).hasNext)
        // Return the first matching pair's sink argument as an iterator
        allMatches.flatMap((src, sink) => List(src, sink))
      }),
      tags = List(QueryTags.default)
    ) 


  @q
  def xss()(implicit context: EngineContext): Query =
    Query.make(
      name = "phpjoern_xss",
      author = Crew.yichao,
      title = "CWE-79(Cross-site Scripting): A parameter is used in an insecure xss related func call.",
      description = """
          |An attacker controlled parameter is used in an insecure xss related func call.
          |
          |If the parameter is not validated and sanitized, this is may result in a cross-site scripting vulnerability.
          |""".stripMargin,
      score = 5,
      withStrRep({ cpg =>
        // $_REQUEST["foo"], $_GET["foo"], $_POST["foo"]
        // are identifier (at the moment)
        def sources = cpg.assignment.source.code(".*_(REQUEST|GET|POST).*")
        def sinks = cpg.call.name("(assert|echo|exit|print|printf|vprintf|print_r|var_dump)")        
        // Find the first matching source-sink pair
        val cartesian = sources.flatMap(i => sinks.map(j => (i, j)))
        val allMatches = cartesian.filter((src, sink) => sink.argument.reachableBy(src).hasNext)
        // Return the first matching pair's sink argument as an iterator
        allMatches.flatMap((src, sink) => List(src, sink))
      }),
      tags = List(QueryTags.xss, QueryTags.default)
    )

}
